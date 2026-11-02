//! Server and client over a real pipe, with a fake handler. Runs without admin rights.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use w4_ipc::api::{HelloResult, method, notification};
use w4_ipc::server::serve;
use w4_ipc::{
    Caller, Client, ClientError, Handler, Notification, PROTOCOL_VERSION, RpcError, ServerConfig,
};

/// Everyone, so the test works under any CI account. Production uses PIPE_SDDL.
const TEST_SDDL: &str = "D:P(A;;GA;;;WD)";

struct Fake;

impl Handler for Fake {
    fn handle(&self, caller: &Caller, method: &str, params: Value) -> Result<Value, RpcError> {
        match method {
            method::HELLO => Ok(json!({ "protocol": PROTOCOL_VERSION, "server_version": "test" })),
            "echo" => Ok(params),
            "whoami" => Ok(json!(caller.pid)),
            "token" => Ok(json!(
                caller
                    .token
                    .as_ref()
                    .map(|t| (&t.user, t.admin, t.elevated))
            )),
            _ => Err(RpcError::method_not_found(method)),
        }
    }
}

fn unique_pipe() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        r"\\.\pipe\win4tress-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

struct Running {
    name: String,
    notes: broadcast::Sender<Notification>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn start() -> Running {
    let name = unique_pipe();
    let (notes, _) = broadcast::channel(16);
    let shutdown = CancellationToken::new();
    let config = ServerConfig {
        pipe_name: name.clone(),
        sddl: TEST_SDDL.into(),
    };
    let task = tokio::spawn(serve(
        config,
        Arc::new(Fake),
        notes.clone(),
        shutdown.clone(),
    ));
    Running {
        name,
        notes,
        shutdown,
        task,
    }
}

async fn connect(name: &str) -> Client {
    for _ in 0..100 {
        match Client::connect(name).await {
            Ok(client) => return client,
            Err(ClientError::NotRunning) => tokio::time::sleep(Duration::from_millis(20)).await,
            Err(e) => panic!("connect failed: {e}"),
        }
    }
    panic!("server never came up");
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_errors_and_notifications() {
    let server = start().await;
    let client = connect(&server.name).await;

    let hello: HelloResult = client.hello("test").await.unwrap();
    assert_eq!(hello.protocol, PROTOCOL_VERSION);

    let echoed: Value = client.call("echo", json!({ "a": [1, 2] })).await.unwrap();
    assert_eq!(echoed, json!({ "a": [1, 2] }));

    let pid: Option<u32> = client.call("whoami", Value::Null).await.unwrap();
    assert_eq!(pid, Some(std::process::id()));

    // The server read our token by impersonating us: same user as this process.
    let token: Option<(String, bool, bool)> = client.call("token", Value::Null).await.unwrap();
    let (user, _admin, _elevated) = token.expect("token read on the first request");
    assert!(user.starts_with("S-1-5-"), "{user}");
    let me = std::process::Command::new("whoami")
        .arg("/user")
        .arg("/fo")
        .arg("csv")
        .arg("/nh")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&me.stdout).contains(&user),
        "token user {user} isn't this process's user"
    );

    match client.call::<_, Value>("nope", Value::Null).await {
        Err(ClientError::Rpc(e)) => assert_eq!(e.code, RpcError::METHOD_NOT_FOUND),
        other => panic!("expected method-not-found, got {other:?}"),
    }

    let mut notes = client.subscribe(&[notification::SAMPLES]).await.unwrap();
    server
        .notes
        .send(Notification::new(
            notification::SAMPLES,
            json!({ "samples": [] }),
        ))
        .unwrap();
    let note = tokio::time::timeout(Duration::from_secs(2), notes.recv())
        .await
        .expect("notification in time")
        .expect("stream open");
    assert_eq!(note.method, notification::SAMPLES);

    server.shutdown.cancel();
    server.task.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(2), client.closed())
        .await
        .expect("client notices shutdown");
    assert!(matches!(
        client.call::<_, Value>("echo", Value::Null).await,
        Err(ClientError::Disconnected)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn many_clients_concurrently() {
    let server = start().await;
    let mut tasks = Vec::new();
    for i in 0..8 {
        let name = server.name.clone();
        tasks.push(tokio::spawn(async move {
            let client = connect(&name).await;
            for j in 0..20 {
                let v: Value = client.call("echo", json!([i, j])).await.unwrap();
                assert_eq!(v, json!([i, j]));
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    server.shutdown.cancel();
    server.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn missing_service_is_reported() {
    let result = Client::connect(r"\\.\pipe\win4tress-test-nobody-home").await;
    assert!(matches!(result, Err(ClientError::NotRunning)));
}

#[tokio::test(flavor = "multi_thread")]
async fn second_server_on_same_name_fails() {
    let server = start().await;
    connect(&server.name).await; // make sure the first one is up
    let (notes, _) = broadcast::channel(1);
    let config = ServerConfig {
        pipe_name: server.name.clone(),
        sddl: TEST_SDDL.into(),
    };
    let second = serve(config, Arc::new(Fake), notes, CancellationToken::new()).await;
    assert!(second.is_err(), "pipe squatting must be refused");
    server.shutdown.cancel();
    server.task.await.unwrap().unwrap();
}

/// A dropped client closes its end, so the server sees the connection end.
/// It used to stay open on both sides for good: a leak per connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_client_closes_its_connection() {
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ServerOptions;

    let name = unique_pipe();
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .unwrap();
    let client = connect(&name).await;
    server.connect().await.unwrap();
    drop(client);
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), server.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the client's end is still open: {read:?}"
    );
}

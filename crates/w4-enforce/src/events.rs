//! Windows Firewall's own event log (SPEC §7.8): rule and setting changes as
//! they happen, so an outside change is put back within about a second instead
//! of at the next 60 s check. The check stays as the backstop: the log can be
//! cleared, turned off or full.

use std::thread::JoinHandle;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, HANDLE, WAIT_OBJECT_0,
};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtNext, EvtRender, EvtRenderEventXml, EvtSubscribe,
    EvtSubscribeToFutureEvents,
};
use windows::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForMultipleObjects,
};
use windows::core::{HSTRING, PCWSTR, w};

use crate::model::NAME_PREFIX;
use crate::{Error, Result};

const CHANNEL: &str = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";

/// Events about firewall settings rather than one rule: a setting changed (per
/// profile or global), Group Policy applied, reset to defaults, all rules deleted.
/// Windows 10 and 11 use different ids for some of these.
const SETTINGS_EVENTS: [u32; 9] = [2002, 2003, 2008, 2032, 2033, 2059, 2060, 2082, 2083];

/// The parts of a change event that matter here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FirewallEvent {
    pub id: u32,
    /// Set on rule events.
    pub rule_name: Option<String>,
    /// The rule's group, on add and modify events (deletes carry only the name).
    pub group: Option<String>,
    /// The program that made the change.
    pub application: Option<String>,
}

impl FirewallEvent {
    /// From the event's XML, as `EvtRender` gives it.
    pub fn parse(xml: &str) -> Option<FirewallEvent> {
        let id = element(xml, "EventID")?.trim().parse().ok()?;
        Some(FirewallEvent {
            id,
            rule_name: data(xml, "RuleName"),
            group: data(xml, "EmbeddedContext"),
            application: data(xml, "ModifyingApplication"),
        })
    }

    /// Whether this could have changed something we enforce: a settings change,
    /// or a change to a rule in `group` or named like ours, made by a program
    /// other than `own_exe` (our own changes are already accounted for).
    pub fn concerns(&self, group: &str, own_exe: &str) -> bool {
        if self
            .application
            .as_deref()
            .is_some_and(|app| app.eq_ignore_ascii_case(own_exe))
        {
            return false;
        }
        match &self.rule_name {
            Some(name) => self.group.as_deref() == Some(group) || name.starts_with(NAME_PREFIX),
            None => SETTINGS_EVENTS.contains(&self.id),
        }
    }

    /// Whether another program's rule changed, or the settings: what Windows
    /// Firewall itself allows or blocks for apps may differ now.
    pub fn about_other_rules(&self, group: &str) -> bool {
        match &self.rule_name {
            Some(name) => self.group.as_deref() != Some(group) && !name.starts_with(NAME_PREFIX),
            None => SETTINGS_EVENTS.contains(&self.id),
        }
    }
}

/// The text of the first `<tag …>text</tag>`.
fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let start = xml.find(&format!("<{tag}"))?;
    let rest = &xml[start + tag.len() + 1..];
    // `<EventID>` or `<EventID Qualifiers='…'>`, not `<EventIDs>`.
    if !rest.starts_with(['>', ' ']) {
        return None;
    }
    let open_end = rest.find('>')?;
    if rest[..open_end].ends_with('/') {
        return Some("");
    }
    let text = &rest[open_end + 1..];
    Some(&text[..text.find('<')?])
}

/// The value of `<Data Name='name'>…</Data>`, unescaped; `None` if absent or empty.
fn data(xml: &str, name: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let open = format!("<Data Name={quote}{name}{quote}");
        let Some(start) = xml.find(&open) else {
            continue;
        };
        let rest = &xml[start + open.len()..];
        let open_end = rest.find('>')?;
        if rest[..open_end].ends_with('/') {
            return None;
        }
        let text = &rest[open_end + 1..];
        let value = unescape(&text[..text.find("</Data>")?]);
        return (!value.is_empty()).then_some(value);
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// A handle the watcher thread may use.
struct SendHandle(HANDLE);
// SAFETY: kernel event handles may be used from any thread.
unsafe impl Send for SendHandle {}

/// Watches the log until dropped.
pub struct Watcher {
    stop: HANDLE,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // SAFETY: `stop` is our event handle, closed only here, after the thread ends.
        unsafe {
            let _ = SetEvent(self.stop);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            let _ = CloseHandle(self.stop);
        }
    }
}

/// Calls `on_event` for every new event in Windows Firewall's log, on a thread
/// of its own. Fails if the log can't be read (no access, or turned off).
pub fn watch(on_event: impl Fn(FirewallEvent) + Send + 'static) -> Result<Watcher> {
    watch_channel(CHANNEL, on_event)
}

fn watch_channel(
    channel: &str,
    on_event: impl Fn(FirewallEvent) + Send + 'static,
) -> Result<Watcher> {
    let w = |what, e| Error::windows(what, e);
    // SAFETY: plain object creation; every handle is closed on each path below
    // or by the thread and `Watcher::drop`.
    unsafe {
        // Manual reset, so a burst read in one go isn't signalled again. Starts
        // signalled: the subscription only signals new events once a first
        // EvtNext has found none (as in Microsoft's pull-subscription sample).
        let signal =
            CreateEventW(None, true, true, PCWSTR::null()).map_err(|e| w("CreateEventW", e))?;
        let stop = match CreateEventW(None, true, false, PCWSTR::null()) {
            Ok(h) => h,
            Err(e) => {
                let _ = CloseHandle(signal);
                return Err(w("CreateEventW", e));
            }
        };
        let subscription = match EvtSubscribe(
            None,
            Some(signal),
            &HSTRING::from(channel),
            w!("*"),
            None,
            None,
            None,
            EvtSubscribeToFutureEvents.0,
        ) {
            Ok(s) => s,
            Err(e) => {
                let _ = CloseHandle(signal);
                let _ = CloseHandle(stop);
                return Err(w("subscribing to the Windows Firewall event log", e));
            }
        };
        let (signal_h, stop_h) = (SendHandle(signal), SendHandle(stop));
        let sub = subscription.0;
        let thread = std::thread::Builder::new()
            .name("w4-firewall-events".into())
            .spawn(move || {
                let (signal, stop) = (signal_h, stop_h);
                let subscription = EVT_HANDLE(sub);
                loop {
                    let woke = WaitForMultipleObjects(&[stop.0, signal.0], false, INFINITE);
                    if woke.0 != WAIT_OBJECT_0.0 + 1 {
                        break; // stop, or a failed wait
                    }
                    // Reset before reading, so an event arriving meanwhile signals again.
                    let _ = ResetEvent(signal.0);
                    drain(subscription, &on_event);
                }
                let _ = EvtClose(subscription);
                let _ = CloseHandle(signal.0);
            });
        match thread {
            Ok(thread) => Ok(Watcher {
                stop,
                thread: Some(thread),
            }),
            Err(e) => {
                let _ = EvtClose(subscription);
                let _ = CloseHandle(signal);
                let _ = CloseHandle(stop);
                Err(Error::Invalid(format!(
                    "starting the event log thread: {e}"
                )))
            }
        }
    }
}

/// Reads every event waiting on the subscription.
///
/// # Safety
/// `subscription` must be a live subscription handle.
unsafe fn drain(subscription: EVT_HANDLE, on_event: &impl Fn(FirewallEvent)) {
    let mut batch = [0isize; 16];
    loop {
        let mut returned = 0u32;
        // SAFETY: the caller guarantees the handle; `batch` and `returned` are ours.
        if let Err(e) = unsafe { EvtNext(subscription, &mut batch, 1000, 0, &mut returned) } {
            if e.code() != ERROR_NO_MORE_ITEMS.to_hresult() {
                tracing::debug!("reading the Windows Firewall event log: {e}");
            }
            return;
        }
        for &raw in &batch[..returned as usize] {
            let event = EVT_HANDLE(raw);
            // SAFETY: each handle EvtNext returned is valid until closed here.
            unsafe {
                if let Some(e) = render(event).as_deref().and_then(FirewallEvent::parse) {
                    on_event(e);
                }
                let _ = EvtClose(event);
            }
        }
    }
}

/// The event as XML.
///
/// # Safety
/// `event` must be a live event handle.
unsafe fn render(event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut count = 0u32;
    // SAFETY: a size query with no buffer, then a render into one of that size.
    unsafe {
        match EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut used,
            &mut count,
        ) {
            Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
            _ => return None,
        }
        let mut buf = vec![0u16; (used as usize).div_ceil(2)];
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            (buf.len() * 2) as u32,
            Some(buf.as_mut_ptr().cast()),
            &mut used,
            &mut count,
        )
        .ok()?;
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODIFIED: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
        <Provider Name='Microsoft-Windows-Windows Firewall With Advanced Security' Guid='{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}'/>\
        <EventID>2099</EventID><Version>0</Version></System><EventData>\
        <Data Name='RuleId'>{34CD5556-DBDD-4CF8-86CD-935F3BB9C89C}</Data>\
        <Data Name='RuleName'>win4tress: Tom &amp; Jerry (Out, Block) #12</Data>\
        <Data Name='ServiceName'></Data>\
        <Data Name='EmbeddedContext'>win4tress</Data>\
        <Data Name='ModifyingApplication'>C:\\Windows\\System32\\netsh.exe</Data>\
        </EventData></Event>";

    #[test]
    fn parses_a_rule_event() {
        let e = FirewallEvent::parse(MODIFIED).unwrap();
        assert_eq!(e.id, 2099);
        assert_eq!(
            e.rule_name.as_deref(),
            Some("win4tress: Tom & Jerry (Out, Block) #12")
        );
        assert_eq!(e.group.as_deref(), Some("win4tress"));
        assert_eq!(
            e.application.as_deref(),
            Some(r"C:\Windows\System32\netsh.exe")
        );
    }

    #[test]
    fn parses_qualified_ids_and_missing_or_empty_fields() {
        let xml = "<Event><System><EventID Qualifiers='0'>2052</EventID></System><EventData>\
            <Data Name=\"RuleName\">Other app</Data><Data Name='EmbeddedContext'/></EventData></Event>";
        let e = FirewallEvent::parse(xml).unwrap();
        assert_eq!(
            (e.id, e.rule_name.as_deref(), e.group, e.application),
            (2052, Some("Other app"), None, None)
        );
        assert_eq!(
            FirewallEvent::parse("<Event><EventIDs>1</EventIDs></Event>"),
            None
        );
        assert_eq!(FirewallEvent::parse("not xml"), None);
    }

    /// Reading the log needs no elevation, so this runs everywhere.
    #[test]
    fn subscribes_and_stops() {
        let watcher = watch(|_| {}).expect("the firewall log can be watched");
        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(watcher);
    }

    /// New events arrive. Changing a firewall rule needs elevation, so this
    /// watches PowerShell's log instead: every powershell.exe writes to it.
    #[test]
    fn delivers_new_events() {
        let (tx, rx) = std::sync::mpsc::channel();
        let watcher = watch_channel("Microsoft-Windows-PowerShell/Operational", move |e| {
            let _ = tx.send(e.id);
        })
        .expect("PowerShell's log can be watched");
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "exit"])
            .status()
            .expect("powershell runs");
        let got = rx.recv_timeout(std::time::Duration::from_secs(10));
        drop(watcher);
        assert!(got.is_ok(), "no event within 10 s");
    }

    #[test]
    fn concerns_our_rules_and_settings_but_not_our_own_changes() {
        let own = r"C:\Program Files\win4tress\win4tress-svc.exe";
        let e = FirewallEvent::parse(MODIFIED).unwrap();
        assert!(e.concerns("win4tress", own));
        // Someone else's rule, in another group.
        let other = FirewallEvent {
            rule_name: Some("Steam".into()),
            group: Some("Steam".into()),
            ..e.clone()
        };
        assert!(!other.concerns("win4tress", own));
        assert!(other.about_other_rules("win4tress"));
        assert!(!e.about_other_rules("win4tress"));
        // A delete carries only the name.
        let deleted = FirewallEvent {
            id: 2052,
            group: None,
            ..e.clone()
        };
        assert!(deleted.concerns("win4tress (console)", own));
        // Our own change, whatever the case of the path.
        let ours = FirewallEvent {
            application: Some(own.to_uppercase()),
            ..e
        };
        assert!(!ours.concerns("win4tress", own));
        // Settings matter; other events without a rule don't.
        let setting = FirewallEvent {
            id: 2082,
            ..Default::default()
        };
        assert!(setting.concerns("win4tress", own));
        let profile_switch = FirewallEvent {
            id: 2010,
            ..Default::default()
        };
        assert!(!profile_switch.concerns("win4tress", own));
    }
}

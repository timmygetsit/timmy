use crossterm::event::{self, Event as CEvent, KeyEvent};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Terminal event envelope.
pub enum Event {
    Key(KeyEvent),
    Tick,
    Resize(u16, u16),
}

/// Event listener reading crossterm events in a background thread.
pub struct EventHandler {
    receiver: mpsc::Receiver<Event>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        let (sender, receiver) = mpsc::channel();
        let s = sender.clone();

        thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or_else(|| Duration::from_secs(0));

                if event::poll(timeout).unwrap_or(false) {
                    #[allow(clippy::collapsible_match)]
                    match event::read() {
                        Ok(CEvent::Key(key)) => {
                            if s.send(Event::Key(key)).is_err() {
                                break;
                            }
                        }
                        Ok(CEvent::Resize(w, h)) => {
                            if s.send(Event::Resize(w, h)).is_err() {
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                if last_tick.elapsed() >= tick_rate {
                    if s.send(Event::Tick).is_err() {
                        break;
                    }
                    last_tick = Instant::now();
                }
            }
        });

        Self { receiver }
    }

    /// Receives the next event.
    pub fn next(&self) -> Result<Event, mpsc::RecvError> {
        self.receiver.recv()
    }
}

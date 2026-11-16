//! TIMMY: AI Agent Resource Manager
//!
//! A lightweight, interactive terminal utility designed for macOS to discover,
//! understand, monitor, and safely manage background processes, services, and open
//! ports left running by AI coding agents and development environments.

pub mod cli;
pub mod config;
pub mod engine;
pub mod model;
pub mod platform;
pub mod safety;
pub mod storage;
pub mod ui;

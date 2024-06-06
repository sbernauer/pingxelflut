#![no_std]

pub const CANVAS_WIDTH: u16 = 1920;
pub const CANVAS_HEIGHT: u16 = 1080;
pub const CANVAS_PIXELS: u32 = CANVAS_WIDTH as u32 * CANVAS_HEIGHT as u32;

pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_ECHO_RESPONSE: u8 = 0;

pub const MSG_GET_SIZE_REQUEST: u8 = 0xaa;
pub const MSG_SIZE_RESPONSE: u8 = 0xbb;
pub const MSG_SET_PIXEL: u8 = 0xcc;

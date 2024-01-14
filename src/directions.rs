#![allow(dead_code)]

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum IncomingDirection {
    FromServer,
    FromClient,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum OutgoingDirection {
    ToServer,
    ToClient,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum Direction {
    Incoming(IncomingDirection),
    Outgoing(OutgoingDirection),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct DataEvent<'a, T> {
    pub(crate) direction: T,
    pub(crate) buffer: &'a [u8],
}

pub(crate) type IncomingDataEvent<'a> = DataEvent<'a, IncomingDirection>;
pub(crate) type OutgoingDataEvent<'a> = DataEvent<'a, OutgoingDirection>;

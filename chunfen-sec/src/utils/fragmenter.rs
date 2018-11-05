use crate::data::{BorrowedMessage, ContentType, PlainText};
use std::collections::VecDeque;

pub const MAX_FRAGMENT_LEN: usize = 16 * 1024;

pub fn borrow_split<'a>(ty: ContentType,
                        src: &'a [u8],
                        out: &mut VecDeque<BorrowedMessage<'a>>) {
    for fragment in src.chunks(MAX_FRAGMENT_LEN) {
        let bm = BorrowedMessage { ty, fragment, };
        out.push_back(bm);
    }
}

pub fn split(msg: PlainText, out: &mut VecDeque<PlainText>) {
    if msg.fragment.len() <= MAX_FRAGMENT_LEN {
        out.push_back(msg);
        return
    }

    let PlainText { content_type, fragment } = msg;
    for chunk in fragment.chunks(MAX_FRAGMENT_LEN) {
        let m = PlainText {
            content_type,
            fragment: chunk.to_vec(),
        };
        out.push_back(m);
    }
}

use bitcoin::{
    opcodes::all::{OP_ENDIF, OP_FROMALTSTACK, OP_GREATERTHAN, OP_TOALTSTACK},
    script::Builder,
};

use bitcoin_script::define_pushable;
use bitcoin_script::script;

define_pushable!();

#[test]
fn test_plain() {
    let script = script! (
        OP_ADD
        OP_ADD
        OP_ADD
    );
    script.compile();
    let (x, y) = script.get_stack_status();
    assert_eq!(x, -4);
    assert_eq!(y, -3);
}

fn inner_fn1() -> pushable::Builder {
    script!(
        {10}
        OP_ROLL
        {2}
        OP_ROLL
        OP_ADD
    )
}

fn inner_fn2() -> pushable::Builder {
    script!(
        {1}
        OP_DUP
        OP_TOALTSTACK
        {2}
        OP_DUP
        OP_TOALTSTACK
        OP_GREATERTHAN
        OP_IF
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_ADD
        OP_ELSE
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_SUB
        OP_ENDIF
    )
}

#[test]
fn test_deepthest() {
    let script = script! (
        {inner_fn1()}
        {inner_fn1()}
        OP_ADD
    );
    script.compile();
    let (x, y) = script.get_stack_status();
    assert_eq!([x, y], [-10, 1]);

    let script = script! (
     {inner_fn2()}
     {inner_fn2()}
     OP_ADD
    );
    script.compile();
    let (x, y) = script.get_stack_status();
    assert_eq!([x, y], [0, 1]);
}

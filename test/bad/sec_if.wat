(module
  (import "js" "memory" (memory 2))

  (func $get untrusted (param $addr i32)
    (result i32)

    (if (result i32) (i32.eq (get_local $addr) (i32.const 0))
        (then (i32.const 1))
        (else (i32.const 2))
    )
  )
)

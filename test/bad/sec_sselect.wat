(module
  (import "js" "memory" (memory 1 2))

  (func $get untrusted (param $a s32)
    (result i32)

    (local $addr i32)

    (set_local $addr (sselect (i32.const 0) (i32.const 10) (get_local $a)))

    (i32.load (get_local $addr))
  )
)

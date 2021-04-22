(module
  (import "js" "memory" (memory 2))

  (func $get untrusted (param $iters i32)
    (result i32)
    (local $res i32)
    (local $i i32)

    (set_local $res (i32.const 0))
    (set_local $i (i32.const 0))

    (block
        (loop
            (br_if 1 (i32.ge_u (get_local $i) (get_local $iters)))

            (set_local $i (i32.add (get_local $i) (i32.const 1)))

            (set_local $res (i32.add (get_local $res) (get_local $i)))
            
            (br 0)
        )
    )

    (return (get_local $res))
  )
)

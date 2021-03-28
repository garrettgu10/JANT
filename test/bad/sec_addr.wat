(module
  (import "js" "memory" (memory 2))

  (func $get untrusted (param $addr i32)
    (result i32)

    (i32.load (get_local $addr))
  )
)

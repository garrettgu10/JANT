(module
  (import "js" "memory" (memory 2))
  ;;test that a secret store to a public memory is detected
  (func $get untrusted (param $val i32)
    (i32.store (i32.const 0) (get_local $val))
  )
)

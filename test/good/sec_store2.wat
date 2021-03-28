(module
  (import "js" "memory" (memory secret 2))
  ;;test that a secret store to a public memory is detected
  (func $get untrusted (param $val i32)
    (s32.store (i32.const 0) (s32.classify (get_local $val)))
  )
)

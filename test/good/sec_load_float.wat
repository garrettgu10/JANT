(module
  (import "js" "memory" (memory 2))
  ;;test that a load from secret memory that is later used to do non-DIT stuff is detected
  (func $get untrusted (param $addr i32)
    (result i32)

    (i32.trunc_f32_s (f32.add (f32.convert_i32_s (i32.load(get_local $addr))) (f32.const 0.2)))
  )
)

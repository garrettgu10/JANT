(module
  (import "js" "memory" (memory 2))

  (func $f1 trusted (param $a s32)
    (result i32)

    (call $f2 (get_local $a))
  )

  (func $f2 trusted (param $a s32)
    (result i32)
    (i32.trunc_f32_s (f32.add (f32.convert_i32_s (i32.declassify (get_local $a))) (f32.const 0.2)))
  )
)

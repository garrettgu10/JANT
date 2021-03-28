(module
  (import "js" "memory" (memory 1))
  (func $f1 untrusted (result s32)
    (s32.classify (call $f2))
  )

  (func $f2 untrusted (result i32) 
    (i32.const 30)
  )
)

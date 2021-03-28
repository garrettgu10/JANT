(module
  (import "js" "memory" (memory 1))
  ;; test getting a secret value as a result value and resulting it as a public value
  (func $f1 untrusted (result i32)
    (call $f2)
  )

  (func $f2 untrusted (result i32) 
    (i32.const 30)
  )
)

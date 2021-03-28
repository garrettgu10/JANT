(module
  (import "js" "memory" (memory 1))
  ;; test passing in a secret value as a public parameter
  (func $f1 untrusted (param $a s32)
    (call $f2 (get_local $a))
  )

  (func $f2 untrusted (param $a s32) 

  )
)

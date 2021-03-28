(module
  (import "js" "memory" (memory 1))
  (func $f1 untrusted (param $a i32)
    (call $f2 (get_local $a))
  )

  (func $f2 untrusted (param $a i32) 

  )
)

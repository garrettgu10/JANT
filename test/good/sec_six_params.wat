(module
  (import "js" "memory" (memory 1))
  (func $f1 untrusted (param $a i32) (param $b i64) (param $c i64) (param $d i32) (param $e i32) (param $f i32)
    (call $f2 (get_local $a) (get_local $b) (get_local $c) (get_local $d) (get_local $e) (get_local $f))
  )

  (func $f2 untrusted (param $a i32) (param $b i64) (param $c i64) (param $d i32) (param $e i32) (param $f i32)

  )
)

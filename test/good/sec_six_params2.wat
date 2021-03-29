(module
  (import "js" "memory" (memory 1))
  ;; test passing in a secret values as public parameters
  (func $f1 untrusted (param $a s32) (param $b s64) (param $c s64) (param $d s32) (param $e s32) (param $f s32)
    (call $f2 (get_local $a) (get_local $b) (get_local $c) (get_local $d) (get_local $e) (get_local $f))
  )

  (func $f2 untrusted (param $a s32) (param $b s64) (param $c s64) (param $d s32) (param $e s32) (param $f s32)

  )
)

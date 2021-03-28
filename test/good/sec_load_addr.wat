(module
  (import "js" "memory" (memory 2))
  ;;test that a load from secret memory that is later used to index into memory is detected
  (func $get untrusted (param $addr i32)
    (result i32)

    (i32.load (i32.load (get_local $addr)))
  )
)

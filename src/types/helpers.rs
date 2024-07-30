
pub fn print_type_of<T>(_: &T) {
    println!("Type: {}", std::any::type_name::<T>());
}

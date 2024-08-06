use svg::Document;
use svg::node::element::Path;
use svg::node::element::path::Data;
use svg::node::Text;

#[test]
fn test_create_svg() {
    let t = Text::new("endepointe");
    dbg!(t);

    let data = Data::new()
    .move_to((10, 100))
    .line_by((0, 50))
    .line_by((50, 0))
    .line_by((0, -50))
    .close();

    let path = Path::new()
        .set("fill", "none")
        .set("stroke", "black")
        .set("stroke-width", 3)
        .set("d", data);

    let document = Document::new()
        .set("viewBox", (0, 0, 200, 200))
        .add(path);

    svg::save("image.svg", &document).unwrap();
}


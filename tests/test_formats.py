"""
Tests for FormatDatabase
"""


from filo.formats import FormatDatabase


def test_database_initialization():
    """Test database loads formats."""
    db = FormatDatabase()
    assert db.count() > 0
    assert len(db) > 0


def test_get_format():
    """Test getting format specification."""
    db = FormatDatabase()
    
    png_spec = db.get_format("png")
    assert png_spec is not None
    assert png_spec.format == "png"
    assert "image/png" in png_spec.mime
    assert "png" in png_spec.extensions


def test_list_formats():
    """Test listing all formats."""
    db = FormatDatabase()
    
    formats = db.list_formats()
    assert isinstance(formats, list)
    assert len(formats) > 0
    assert "png" in formats
    assert "jpeg" in formats


def test_get_formats_by_category():
    """Test filtering by category."""
    db = FormatDatabase()
    
    image_formats = db.get_formats_by_category("raster_image")
    assert len(image_formats) > 0
    
    format_names = [spec.format for spec in image_formats]
    assert "png" in format_names
    assert "jpeg" in format_names


def test_get_formats_by_extension():
    """Test filtering by extension."""
    db = FormatDatabase()
    
    png_formats = db.get_formats_by_extension("png")
    assert len(png_formats) == 1
    assert png_formats[0].format == "png"
    
    # Test with leading dot
    png_formats2 = db.get_formats_by_extension(".png")
    assert len(png_formats2) == 1


def test_format_contains():
    """Test __contains__ method."""
    db = FormatDatabase()
    
    assert "png" in db
    assert "jpeg" in db
    assert "nonexistent" not in db

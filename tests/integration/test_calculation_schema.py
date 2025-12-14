import pytest
from pydantic import ValidationError
from uuid import uuid4
from datetime import datetime
from app.schemas.calculation import (
    CalculationCreate,
    CalculationUpdate,
    CalculationResponse
)

def test_calculation_create_valid():
    """Test creating a valid CalculationCreate schema."""
    data = {
        "type": "addition",
        "inputs": [10.5, 3.0],
        "user_id": uuid4()
    }
    calc = CalculationCreate(**data)
    assert calc.type == "addition"
    assert calc.inputs == [10.5, 3.0]
    assert calc.user_id is not None

def test_calculation_create_missing_type():
    """Test CalculationCreate fails if 'type' is missing."""
    data = {
        "inputs": [10.5, 3.0],
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    # Look for a substring that indicates a missing required field.
    assert "required" in str(exc_info.value).lower()

def test_calculation_create_missing_inputs():
    """Test CalculationCreate fails if 'inputs' is missing."""
    data = {
        "type": "multiplication",
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    assert "required" in str(exc_info.value).lower()

def test_calculation_create_invalid_inputs():
    """Test CalculationCreate fails if 'inputs' is not a list of floats."""
    data = {
        "type": "division",
        "inputs": "not-a-list",
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    error_message = str(exc_info.value)
    # Ensure that our custom error message is present (case-insensitive)
    assert "input should be a valid list" in error_message.lower(), error_message

def test_calculation_create_unsupported_type():
    """Test CalculationCreate fails if an unsupported calculation type is provided."""
    data = {
        "type": "square_root",  # Unsupported type
        "inputs": [25],
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    error_message = str(exc_info.value).lower()
    # Check that the error message indicates the value is not permitted.
    assert "one of" in error_message or "not a valid" in error_message

def test_calculation_update_valid():
    """Test a valid partial update with CalculationUpdate."""
    data = {
        "inputs": [42.0, 7.0]
    }
    calc_update = CalculationUpdate(**data)
    assert calc_update.inputs == [42.0, 7.0]

def test_calculation_update_no_fields():
    """Test that an empty update is allowed (i.e., no fields)."""
    calc_update = CalculationUpdate()
    assert calc_update.inputs is None

def test_calculation_response_valid():
    """Test creating a valid CalculationResponse schema."""
    data = {
        "id": uuid4(),
        "user_id": uuid4(),
        "type": "subtraction",
        "inputs": [20, 5],
        "result": 15.5,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    calc_response = CalculationResponse(**data)
    assert calc_response.id is not None
    assert calc_response.user_id is not None
    assert calc_response.type == "subtraction"
    assert calc_response.inputs == [20, 5]
    assert calc_response.result == 15.5



# ==============================================================================
# Additional Validation Tests
# ==============================================================================

def test_calculation_update_single_input_validation():
    """
    Test that CalculationUpdate rejects single input.
    
    Note: With only 1 item, the Field-level min_items=2 constraint catches this
    BEFORE the model_validator runs. Pydantic validates Field constraints before
    running model validators.
    """
    data = {
        "inputs": [10]  # Only one input - caught by min_items=2
    }
    
    with pytest.raises(ValidationError) as exc_info:
        CalculationUpdate(**data)
    
    error_message = str(exc_info.value).lower()
    # Pydantic's min_items constraint generates messages with these patterns
    assert (
        "at least" in error_message or 
        "min" in error_message or
        "list should have at least" in error_message
    ), f"Unexpected error: {exc_info.value}"


def test_calculation_update_empty_inputs():
    """Test that CalculationUpdate rejects empty inputs list"""
    data = {
        "inputs": []  # Empty list - should fail!
    }
    
    with pytest.raises(ValidationError) as exc_info:
        CalculationUpdate(**data)
    
    error_message = str(exc_info.value).lower()
    # Pydantic's min_items constraint error message contains "at least" or "min"
    assert ("at least" in error_message or "min" in error_message), f"Unexpected error: {exc_info.value}"





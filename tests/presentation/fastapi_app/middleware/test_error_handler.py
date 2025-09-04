"""
Tests para el manejador de errores.

Estos tests verifican el manejo centralizado de errores en la aplicación.
"""

import pytest
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from src.presentation.fastapi_app.middleware.error_handler import ErrorHandler
from src.domain.entities.dto import ErrorResponseDTO


class TestErrorHandler:
    """Tests para ErrorHandler."""
    
    def test_handle_validation_error(self):
        """Test manejo de errores de validación."""
        # Arrange
        validation_error = RequestValidationError([
            {"loc": ("body", "logs", 0, "cpu_usage"), "msg": "ensure this value is greater than or equal to 0", "type": "value_error.number.not_ge"},
            {"loc": ("body", "logs", 1, "device_id"), "msg": "field required", "type": "value_error.missing"}
        ])
        
        # Act
        response = ErrorHandler.handle_validation_error(validation_error)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 422
        
        data = response.body.decode()
        assert "VALIDATION_ERROR" in data
        assert "Error de validación en los datos de entrada" in data
        assert "validation_errors" in data
        assert "cpu_usage" in data
        assert "device_id" in data
    
    def test_handle_validation_error_empty_errors(self):
        """Test manejo de errores de validación vacíos."""
        # Arrange
        validation_error = RequestValidationError([])
        
        # Act
        response = ErrorHandler.handle_validation_error(validation_error)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 422
        
        data = response.body.decode()
        assert "VALIDATION_ERROR" in data
        assert "Error de validación en los datos de entrada" in data
        assert "validation_errors" in data
    
    def test_handle_http_exception(self):
        """Test manejo de excepciones HTTP."""
        # Arrange
        http_exception = HTTPException(status_code=404, detail="Resource not found")
        
        # Act
        response = ErrorHandler.handle_http_exception(http_exception)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 404
        
        data = response.body.decode()
        assert "HTTP_404" in data
        assert "Resource not found" in data
        assert "status_code" in data
        assert "404" in data
    
    def test_handle_http_exception_different_status_codes(self):
        """Test manejo de excepciones HTTP con diferentes códigos de estado."""
        # Test 400 Bad Request
        http_exception_400 = HTTPException(status_code=400, detail="Bad Request")
        response_400 = ErrorHandler.handle_http_exception(http_exception_400)
        assert response_400.status_code == 400
        assert "HTTP_400" in response_400.body.decode()
        
        # Test 500 Internal Server Error
        http_exception_500 = HTTPException(status_code=500, detail="Internal Server Error")
        response_500 = ErrorHandler.handle_http_exception(http_exception_500)
        assert response_500.status_code == 500
        assert "HTTP_500" in response_500.body.decode()
        
        # Test 403 Forbidden
        http_exception_403 = HTTPException(status_code=403, detail="Forbidden")
        response_403 = ErrorHandler.handle_http_exception(http_exception_403)
        assert response_403.status_code == 403
        assert "HTTP_403" in response_403.body.decode()
    
    def test_handle_generic_exception(self):
        """Test manejo de excepciones genéricas."""
        # Arrange
        generic_exception = Exception("Something went wrong")
        
        # Act
        response = ErrorHandler.handle_generic_exception(generic_exception)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 500
        
        data = response.body.decode()
        assert "INTERNAL_SERVER_ERROR" in data
        assert "Error interno del servidor" in data
        assert "exception_type" in data
        assert "Exception" in data
    
    def test_handle_generic_exception_different_types(self):
        """Test manejo de diferentes tipos de excepciones genéricas."""
        # Test ValueError
        value_error = ValueError("Invalid value")
        response_value = ErrorHandler.handle_generic_exception(value_error)
        assert response_value.status_code == 500
        assert "INTERNAL_SERVER_ERROR" in response_value.body.decode()
        assert "ValueError" in response_value.body.decode()
        
        # Test TypeError
        type_error = TypeError("Invalid type")
        response_type = ErrorHandler.handle_generic_exception(type_error)
        assert response_type.status_code == 500
        assert "INTERNAL_SERVER_ERROR" in response_type.body.decode()
        assert "TypeError" in response_type.body.decode()
        
        # Test RuntimeError
        runtime_error = RuntimeError("Runtime error occurred")
        response_runtime = ErrorHandler.handle_generic_exception(runtime_error)
        assert response_runtime.status_code == 500
        assert "INTERNAL_SERVER_ERROR" in response_runtime.body.decode()
        assert "RuntimeError" in response_runtime.body.decode()
    
    def test_handle_file_not_found(self):
        """Test manejo de errores de archivo no encontrado."""
        # Arrange
        file_not_found = FileNotFoundError("Dataset no encontrado")
        
        # Act
        response = ErrorHandler.handle_file_not_found(file_not_found)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 404
        
        data = response.body.decode()
        assert "FILE_NOT_FOUND" in data
        assert "Dataset no encontrado" in data
        assert "FileNotFoundError" in data
    
    def test_handle_file_not_found_different_messages(self):
        """Test manejo de FileNotFoundError con diferentes mensajes."""
        # Test con mensaje personalizado
        file_not_found_custom = FileNotFoundError("Custom file not found message")
        response_custom = ErrorHandler.handle_file_not_found(file_not_found_custom)
        assert response_custom.status_code == 404
        assert "FILE_NOT_FOUND" in response_custom.body.decode()
        assert "Custom file not found message" in response_custom.body.decode()
        
        # Test con mensaje vacío
        file_not_found_empty = FileNotFoundError("")
        response_empty = ErrorHandler.handle_file_not_found(file_not_found_empty)
        assert response_empty.status_code == 404
        assert "FILE_NOT_FOUND" in response_empty.body.decode()
    
    def test_get_exception_handler(self):
        """Test que el manejador de excepciones retorna una función válida."""
        # Act
        handler = ErrorHandler.get_exception_handler()
        
        # Assert
        assert callable(handler)
    
    def test_exception_handler_with_validation_error(self):
        """Test que el manejador de excepciones maneja RequestValidationError."""
        # Arrange
        validation_error = RequestValidationError([
            {"loc": ("body", "cpu_usage"), "msg": "ensure this value is greater than or equal to 0", "type": "value_error.number.not_ge"}
        ])
        request = Request({"type": "http", "method": "POST", "url": "http://test"})
        
        # Act
        handler = ErrorHandler.get_exception_handler()
        response = handler(request, validation_error)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 422
        assert "VALIDATION_ERROR" in response.body.decode()
    
    def test_exception_handler_with_http_exception(self):
        """Test que el manejador de excepciones maneja HTTPException."""
        # Arrange
        http_exception = HTTPException(status_code=404, detail="Not found")
        request = Request({"type": "http", "method": "GET", "url": "http://test"})
        
        # Act
        handler = ErrorHandler.get_exception_handler()
        response = handler(request, http_exception)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 404
        assert "HTTP_404" in response.body.decode()
    
    def test_exception_handler_with_file_not_found(self):
        """Test que el manejador de excepciones maneja FileNotFoundError."""
        # Arrange
        file_not_found = FileNotFoundError("File not found")
        request = Request({"type": "http", "method": "GET", "url": "http://test"})
        
        # Act
        handler = ErrorHandler.get_exception_handler()
        response = handler(request, file_not_found)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 404
        assert "FILE_NOT_FOUND" in response.body.decode()
    
    def test_exception_handler_with_generic_exception(self):
        """Test que el manejador de excepciones maneja excepciones genéricas."""
        # Arrange
        generic_exception = Exception("Generic error")
        request = Request({"type": "http", "method": "GET", "url": "http://test"})
        
        # Act
        handler = ErrorHandler.get_exception_handler()
        response = handler(request, generic_exception)
        
        # Assert
        assert isinstance(response, JSONResponse)
        assert response.status_code == 500
        assert "INTERNAL_SERVER_ERROR" in response.body.decode()
    
    def test_error_response_dto_structure(self):
        """Test que las respuestas de error siguen la estructura del DTO."""
        # Arrange
        validation_error = RequestValidationError([
            {"loc": ("body", "cpu_usage"), "msg": "ensure this value is greater than or equal to 0", "type": "value_error.number.not_ge"}
        ])
        
        # Act
        response = ErrorHandler.handle_validation_error(validation_error)
        
        # Assert
        assert isinstance(response, JSONResponse)
        data = response.body.decode()
        
        # Verificar que la respuesta contiene los campos del ErrorResponseDTO
        assert "error_code" in data
        assert "message" in data
        assert "details" in data
    
    def test_error_response_dto_with_trace_id(self):
        """Test que las respuestas de error pueden incluir trace_id."""
        # Arrange
        http_exception = HTTPException(status_code=500, detail="Internal error")
        
        # Act
        response = ErrorHandler.handle_http_exception(http_exception)
        
        # Assert
        assert isinstance(response, JSONResponse)
        data = response.body.decode()
        
        # Verificar que la respuesta contiene los campos del ErrorResponseDTO
        assert "error_code" in data
        assert "message" in data
        assert "details" in data
        # trace_id es opcional, no se incluye en este caso

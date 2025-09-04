"""
Manejo centralizado de errores para la aplicación FastAPI.

Este módulo proporciona un manejo consistente de errores a través de toda la aplicación,
siguiendo los principios de Clean Architecture.
"""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import logging
import traceback
from typing import Union

from ...domain.entities.dto import ErrorResponseDTO

logger = logging.getLogger(__name__)


class ErrorHandler:
    """Manejador centralizado de errores."""
    
    @staticmethod
    def handle_validation_error(exc: RequestValidationError) -> JSONResponse:
        """Maneja errores de validación de Pydantic."""
        errors = []
        for error in exc.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            errors.append(f"{field}: {error['msg']}")
        
        error_response = ErrorResponseDTO(
            error_code="VALIDATION_ERROR",
            message="Error de validación en los datos de entrada",
            details={"validation_errors": errors}
        )
        
        return JSONResponse(
            status_code=422,
            content=error_response.__dict__
        )
    
    @staticmethod
    def handle_http_exception(exc: HTTPException) -> JSONResponse:
        """Maneja excepciones HTTP personalizadas."""
        error_response = ErrorResponseDTO(
            error_code=f"HTTP_{exc.status_code}",
            message=exc.detail,
            details={"status_code": exc.status_code}
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=error_response.__dict__
        )
    
    @staticmethod
    def handle_generic_exception(exc: Exception) -> JSONResponse:
        """Maneja excepciones genéricas no controladas."""
        logger.error(f"Error no controlado: {str(exc)}", exc_info=True)
        
        error_response = ErrorResponseDTO(
            error_code="INTERNAL_SERVER_ERROR",
            message="Error interno del servidor",
            details={"exception_type": type(exc).__name__}
        )
        
        return JSONResponse(
            status_code=500,
            content=error_response.__dict__
        )
    
    @staticmethod
    def handle_file_not_found(exc: FileNotFoundError) -> JSONResponse:
        """Maneja errores de archivo no encontrado."""
        error_response = ErrorResponseDTO(
            error_code="FILE_NOT_FOUND",
            message=str(exc),
            details={"error_type": "FileNotFoundError"}
        )
        
        return JSONResponse(
            status_code=404,
            content=error_response.__dict__
        )
    
    @staticmethod
    def get_exception_handler():
        """Retorna el manejador de excepciones para FastAPI."""
        async def exception_handler(request: Request, exc: Exception) -> JSONResponse:
            if isinstance(exc, RequestValidationError):
                return ErrorHandler.handle_validation_error(exc)
            elif isinstance(exc, HTTPException):
                return ErrorHandler.handle_http_exception(exc)
            elif isinstance(exc, FileNotFoundError):
                return ErrorHandler.handle_file_not_found(exc)
            else:
                return ErrorHandler.handle_generic_exception(exc)
        
        return exception_handler

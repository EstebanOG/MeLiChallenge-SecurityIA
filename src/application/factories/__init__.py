"""
Factories para la capa de aplicación.

Estos factories se encargan de crear casos de uso con sus dependencias
inyectadas, siguiendo los principios de Clean Architecture.
"""

from .use_case_factory import UseCaseFactory

__all__ = ["UseCaseFactory"]
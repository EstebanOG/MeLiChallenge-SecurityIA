from src.frameworks.web import create_app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    # Use import string for reload support
    uvicorn.run("wsgi:app", host="0.0.0.0", port=8000, reload=True)



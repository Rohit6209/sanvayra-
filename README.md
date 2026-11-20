# Sanvyra – Smart Department Knowledge Portal with RAG AI
Run:
    pip install -r requirements.txt
    uvicorn main:app --reload
Open http://127.0.0.1:8000
Default HOD login: hod@sanvyra.com / admin123  (change via env HOD_EMAIL, HOD_PASSWORD)
Optional env: GEMINI_API_KEY (LLM answers), GEMINI_MODEL, SECRET
Without GEMINI_API_KEY the chatbot returns the most relevant excerpts + sources.
Database: SQLite (sanvyra.db, auto-created, pure Python). Uploads in /uploads.

# Contributing

1. Create a focused feature branch.
2. Keep detection logic in `backend/app/services/detection.py` and transport concerns in `backend/app/api`.
3. Add tests for every new detector and relevant false-positive boundary cases.
4. Run backend tests and the frontend production build before opening a pull request.
5. Keep detection rules explainable: findings should include evidence and response guidance.

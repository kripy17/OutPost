"""API routes for local security validation corpus & accuracy metrics."""

from typing import Any

from fastapi import APIRouter

from ..services import validation_corpus

router = APIRouter(prefix="/corpus", tags=["Validation Corpus"])


@router.get("/report", response_model=None)
def get_validation_corpus_report() -> dict[str, Any]:
    """Execute validation corpus evaluation and return detection rate and false positive metrics."""
    return validation_corpus.evaluate_validation_corpus()

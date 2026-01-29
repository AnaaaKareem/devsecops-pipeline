"""
SQLAlchemy data models for the AI Agent.

This module defines the schema for Scans, Findings, and user Feedback.
"""

from sqlalchemy import Column, Integer, String, Text, ForeignKey, Float, DateTime, Boolean
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime
from .database import Base
from pydantic import BaseModel

class Scan(Base):
    """
    Represents a single security scan execution on a project commit.
    """
    __tablename__ = "scans"
    
    # --- Primary Key & Identifiers ---
    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, index=True)       # e.g. "user/repo"
    commit_sha = Column(String, index=True)         # Git commit hash scanned
    commit_sha = Column(String, index=True)         # Git commit hash scanned
    timestamp = Column(DateTime, default=datetime.utcnow)
    reference_id = Column(String, index=True, nullable=True)  # UUID for async status tracking
    
    # --- Relationships ---
    findings = relationship("Finding", back_populates="scan")  # One-to-many
    metrics = relationship("PipelineMetric", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    
    # --- Multi-Platform Support ---
    source_platform = Column(String, default="github")  # github, gitlab, jenkins, azure
    repo_provider = Column(String)                      # github, gitlab, jenkins
    repo_url = Column(String)                           # Full repository URL
    ci_provider = Column(String)                        # github-actions, gitlab-ci, jenkins
    branch = Column(String)                             # Branch name being scanned
    
    # --- URLs & Status ---
    source_url = Column(String, nullable=True)          # Base URL for Enterprise/Self-Hosted
    target_url = Column(String, nullable=True)          # Temporary test environment URL (DAST)
    ci_job_url = Column(String, nullable=True)          # Link to CI run log
    status = Column(String, default="pending")          # pending, processing, completed, failed

class Finding(Base):
    """
    Represents a single security vulnerability/finding detected by a scanner tool.
    Stores both the original scanner data and the AI's subsequent analysis.
    """
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    
    # --- Time Tracking ---
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)       # Set when finding is fixed
    
    triage_decision = Column(String)      # "TP" (True Positive) or "FP" (False Positive)
    sandbox_logs = Column(Text)           # Execution logs from verification sandbox
    
    # --- Scanner Output Fields ---
    tool = Column(String)                 # Scanner name (Semgrep, Gitleaks, etc.)
    rule_id = Column(String)              # Specific rule violated
    file = Column(String)                 # File path relative to repo root
    dast_endpoint = Column(String, nullable=True)  # URL/Endpoint for DAST findings
    line = Column(Integer)                # Line number of the finding
    message = Column(Text)                # Original description from scanner
    
    # --- AI Analysis Fields ---
    snippet = Column(Text)                # Code snippet extracted from source
    ai_verdict = Column(String)           # "TP" or "FP" from LLM analysis
    ai_confidence = Column(Float, default=0.0)  # Confidence score (0.0 - 1.0)
    ai_reasoning = Column(Text)           # LLM's explanation
    risk_score = Column(Float)            # Numeric risk (1.0 - 10.0)
    severity = Column(String)             # "Critical", "High", "Medium", "Low"
    remediation_patch = Column(Text)      # AI-generated code fix
    
    # --- Agentic Workflow Outcomes ---
    red_team_success = Column(Boolean, default=False)  # Did exploit verification succeed?
    red_team_output = Column(Text)                     # Exploit attempt output
    pr_url = Column(String)                            # URL of created Pull Request
    pr_error = Column(String)                          # Error if PR creation failed
    
    # --- Production Readiness ---
    regression_test_passed = Column(Boolean, default=None)     # Did fix break tests?
    is_exported_for_training = Column(Boolean, default=False)  # Used for RLHF?
    compliance_control = Column(String, nullable=True)         # e.g. "SOC2-CC7.1"

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    feedbacks = relationship("Feedback", back_populates="finding")

class Feedback(Base):
    """
    Stores human feedback (RLHF) on AI decisions for future fine-tuning.
    """
    __tablename__ = "feedbacks"
    
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    
    user_verdict = Column(String) # The human's decision (True Positive/False Positive)
    comments = Column(Text)       # Optional educational context or correction
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationship back to Finding
    finding = relationship("Finding", back_populates="feedbacks")

class FeedbackRequest(BaseModel):
    """
    Pydantic model for validating feedback API requests.
    """
    finding_id: int
    verdict: str
    comments: str

class PipelineMetric(Base):
    """
    Stores scalar metrics from CI/CD pipelines to train anomaly detection models.
    """
    __tablename__ = "pipeline_metrics"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))

    build_duration_seconds = Column(Float, default=0.0)
    artifact_size_bytes = Column(Integer, default=0)
    num_changed_files = Column(Integer, default=0)
    test_coverage_percent = Column(Float, default=0.0)
    
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("Scan", back_populates="metrics")

class EPSSData(Base):
    """
    Stores daily Exploit Prediction Scoring System (EPSS) data.
    Used to prioritize findings based on real-world exploit probability.
    """
    __tablename__ = "epss_data"
    cve_id = Column(String, primary_key=True, index=True)
    probability = Column(Float) # 0.0 to 1.0
    percentile = Column(Float)
    last_updated = Column(DateTime, default=datetime.utcnow)



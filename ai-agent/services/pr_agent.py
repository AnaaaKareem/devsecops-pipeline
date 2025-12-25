"""
GitHub PR Agent Service.

Handles the creation of git branches, commits, and Pull Requests to automate
remediation of security findings.
"""

import os
import subprocess
from github import Github

def create_security_pr(repo_name, branch_name, patch_content, file_path, issue_message, temp_dir):
    """
    Creates a Pull Request in the target repository with the security fix.

    1. Applies the patch to the file.
    2. Configures local git user.
    3. Checks out a new branch.
    4. Commits and pushes the change using an authenticated URL.
    5. Opens a PR using the GitHub API.

    Args:
        repo_name (str): The repository full name (owner/repo).
        branch_name (str): The name of the new branch.
        patch_content (str): The corrected file content.
        file_path (str): The path to the file being patched.
        issue_message (str): The description of the issue for commit message and PR body.
        temp_dir (str): The local directory where the repo is checked out.

    Returns:
        str: The URL of the created Pull Request.
    """
    full_path = os.path.join(temp_dir, file_path)
    token = os.getenv("GITHUB_TOKEN")
    
    # 🛡️ AUTHENTICATION FORCE: Construct the authenticated URL
    auth_url = f"https://x-access-token:{token}@github.com/{repo_name}.git"
    
    try:
        # 1. Apply the Patch
        with open(full_path, "w") as f:
            f.write(patch_content)
        print(f"📝 Agent: Applied patch to {file_path}")

        # 2. Configure Local Identity (Prevents Error 128 on Commit)
        subprocess.run(["git", "-C", temp_dir, "config", "user.email", "ai-agent@tahwila.ai"], check=True)
        subprocess.run(["git", "-C", temp_dir, "config", "user.name", "AI Security Agent"], check=True)

        # 3. Git Operations
        subprocess.run(["git", "-C", temp_dir, "checkout", "-b", branch_name], check=True)
        subprocess.run(["git", "-C", temp_dir, "add", file_path], check=True)
        subprocess.run(["git", "-C", temp_dir, "commit", "-m", f"🛡️ AI Fix: {issue_message}"], check=True)
        
        # 4. 🔥 THE FINAL PUSH FIX: Push directly to the authenticated URL
        # We replace 'origin' with the 'auth_url' to bypass standard credential checks
        print(f"⬆️ Agent: Pushing {branch_name} to {repo_name}...")
        subprocess.run(["git", "-C", temp_dir, "push", auth_url, branch_name], check=True)
        
        # 5. Create PR via PyGithub
        g = Github(token)
        repo = g.get_repo(repo_name)
        pr = repo.create_pull(
            title=f"🛡️ AI Security Fix: {issue_message}",
            body=f"## 🤖 AI Security Agent Report\n**Vulnerability:** {issue_message}\n\nReview fix for `{file_path}`.",
            head=branch_name,
            base="main"
        )
        return pr.html_url

    except Exception as e:
        print(f"❌ Agent Error: {e}")
        raise e
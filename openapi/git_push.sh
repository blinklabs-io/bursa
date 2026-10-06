#!/bin/sh
# ref: https://help.github.com/articles/adding-an-existing-project-to-github-using-the-command-line/
#
# Usage example: /bin/sh ./git_push.sh wing328 openapi-petstore-perl "minor update" "gitlab.com"

git_user_id=$1
git_repo_id=$2
release_note=$3
git_host=$4

if [ "$git_host" = "" ]; then
    git_host="github.com"
    echo "[INFO] No command line input provided. Set \$git_host to $git_host"
fi

if [ "$git_user_id" = "" ]; then
    git_user_id="blinklabs-io"
    echo "[INFO] No command line input provided. Set \$git_user_id to $git_user_id"
fi

if [ "$git_repo_id" = "" ]; then
    git_repo_id="bursa"
    echo "[INFO] No command line input provided. Set \$git_repo_id to $git_repo_id"
fi

if [ "$release_note" = "" ]; then
    release_note="Minor update"
    echo "[INFO] No command line input provided. Set \$release_note to $release_note"
fi

# Initialize the local directory as a Git repository
git init

# Adds the files in the local repository and stages them for commit.
git add .

# Commits the tracked changes and prepares them to be pushed to a remote repository.
git commit -m "$release_note"

# Runs git with the credential in $GIT_TOKEN, if set. The token reaches git
# through a credential helper that reads it from the environment, so it never
# appears in a remote URL, in .git/config, or in a process argument list. The
# helper runs through a shell, so the user ID reaches it the same way rather
# than being spliced into its text.
git_authenticated() {
    if [ "$GIT_TOKEN" = "" ]; then
        git "$@"
    else
        GIT_USER_ID="$git_user_id" git -c credential.helper= \
            -c 'credential.helper=!f() { test "$1" = get && printf "username=%s\npassword=%s\n" "$GIT_USER_ID" "$GIT_TOKEN"; }; f' \
            "$@"
    fi
}

if [ "$GIT_TOKEN" = "" ]; then
    echo "[INFO] \$GIT_TOKEN (environment variable) is not set. Using the git credential in your environment."
fi

# Sets the new remote
git_remote=$(git remote)
if [ "$git_remote" = "" ]; then # git remote not defined
    git remote add origin https://${git_host}/${git_user_id}/${git_repo_id}.git
fi

git_authenticated pull origin master

# Pushes (Forces) the changes in the local repository up to the remote repository
echo "Git pushing to https://${git_host}/${git_user_id}/${git_repo_id}.git"
git_authenticated push origin master

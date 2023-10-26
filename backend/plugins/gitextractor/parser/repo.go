/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package parser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/apache/incubator-devlake/core/config"
	"github.com/apache/incubator-devlake/core/dal"
	"github.com/apache/incubator-devlake/core/errors"
	"github.com/apache/incubator-devlake/core/log"
	"github.com/apache/incubator-devlake/core/models/domainlayer"
	"github.com/apache/incubator-devlake/core/models/domainlayer/code"
	"github.com/apache/incubator-devlake/core/plugin"
	"github.com/apache/incubator-devlake/plugins/gitextractor/models"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"

	git "github.com/go-git/go-git/v5"
)

const SkipCommitFiles = "SKIP_COMMIT_FILES"

var TypeNotMatchError = "the requested type does not match the type in the ODB"

var splitLinesRegexp = regexp.MustCompile(`[^\n]*(\n|$)`)

type GitRepo struct {
	store   models.Store
	logger  log.Logger
	id      string
	repo    *git.Repository
	cleanup func()
}

// CollectAll The main parser subtask
func (r *GitRepo) CollectAll(subtaskCtx plugin.SubTaskContext) errors.Error {
	subtaskCtx.SetProgress(0, -1)
	err := r.CollectTags(subtaskCtx)
	if err != nil {
		return err
	}
	err = r.CollectBranches(subtaskCtx)
	if err != nil {
		return err
	}
	err = r.CollectCommits(subtaskCtx)
	if err != nil {
		return err
	}
	err = r.CollectDiffLine(subtaskCtx)
	if err != nil {
		return err
	}
	return r.CollectSnapshot(subtaskCtx)
}

// Close resources
func (r *GitRepo) Close() errors.Error {
	defer func() {
		if r.cleanup != nil {
			r.cleanup()
		}
	}()
	return r.store.Close()
}

// CountTags Count git tags subtask
func (r *GitRepo) CountTags() (int, errors.Error) {
	tags, err := r.repo.TagObjects()
	if err != nil {
		return 0, errors.Convert(err)
	}
	count := 0
	err = tags.ForEach(func(t *object.Tag) error {
		count += 1
		return nil
	})
	if err != nil {
		return 0, errors.Convert(err)
	}
	return count, nil
}

// CountBranches count the number of branches in a git repo
func (r *GitRepo) CountBranches(ctx context.Context) (int, errors.Error) {
	head, err := r.repo.Head()
	branchIter, err := r.repo.Branches()
	if err != nil {
		return 0, errors.Convert(err)
	}
	count := 0
	err = branchIter.ForEach(func(branch *plumbing.Reference) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if branch.Name().IsBranch() || branch.Name().IsRemote() {
			if branch.Name().String() != head.Name().String() {
				count++
			}
		}
		return nil
	})
	return count, errors.Convert(err)
}

// CountCommits count the number of commits in a git repo
func (r *GitRepo) CountCommits(ctx context.Context) (int, errors.Error) {
	commitIter, err := r.repo.CommitObjects()
	if err != nil {
		return 0, errors.Convert(err)
	}
	var count int
	err = commitIter.ForEach(func(id *object.Commit) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		count++
		return nil
	})
	return count, errors.Convert(err)
}

// CollectTags Collect Tags data
func (r *GitRepo) CollectTags(subtaskCtx plugin.SubTaskContext) errors.Error {
	tags, err := r.repo.Tags()
	if err != nil {
		return errors.Convert(err)
	}
	err = tags.ForEach(func(tag *plumbing.Reference) error {
		select {
		case <-subtaskCtx.GetContext().Done():
			return subtaskCtx.GetContext().Err()
		default:
		}
		ref := &code.Ref{
			DomainEntity: domainlayer.DomainEntity{Id: fmt.Sprintf("%s:%s", r.id, tag.Name().String())},
			RepoId:       r.id,
			Name:         tag.Name().String(),
			CommitSha:    tag.Hash().String(),
			RefType:      TAG,
		}
		err1 := r.store.Refs(ref)
		if err1 != nil {
			return err1
		}
		subtaskCtx.IncProgress(1)
		return nil
	})
	return errors.Convert(err)
}

// CollectBranches Collect branch data
func (r *GitRepo) CollectBranches(subtaskCtx plugin.SubTaskContext) errors.Error {
	repoInter, err := r.repo.Branches()
	if err != nil {
		return errors.Convert(err)
	}
	head, err := r.repo.Head()
	if err != nil {
		return errors.Convert(err)
	}
	err = repoInter.ForEach(func(branch *plumbing.Reference) error {
		select {
		case <-subtaskCtx.GetContext().Done():
			return subtaskCtx.GetContext().Err()
		default:
		}
		if branch.Name().IsBranch() || branch.Name().IsRemote() {
			var sha string = branch.Hash().String()
			ref := &code.Ref{
				DomainEntity: domainlayer.DomainEntity{Id: fmt.Sprintf("%s:%s", r.id, branch.Name().String())},
				RepoId:       r.id,
				Name:         branch.Name().String(),
				CommitSha:    sha,
				RefType:      BRANCH,
				IsDefault:    branch.Name().String() == head.Name().String(),
			}
			err1 := r.store.Refs(ref)
			if err1 != nil && err1.Error() != TypeNotMatchError {
				return err1
			}
			subtaskCtx.IncProgress(1)
			return nil
		}
		return nil
	})
	return errors.Convert(err)
}

// CollectCommits Collect data from each commit, we can also get the diff line
func (r *GitRepo) CollectCommits(subtaskCtx plugin.SubTaskContext) errors.Error {
	db := subtaskCtx.GetDal()
	components := make([]code.Component, 0)
	err := db.All(&components, dal.From(components), dal.Where("repo_id= ?", r.id))
	if err != nil {
		return err
	}
	componentMap := make(map[string]*regexp.Regexp)
	for _, component := range components {
		componentMap[component.Name] = regexp.MustCompile(component.PathRegex)
	}
	commitIter, err1 := r.repo.CommitObjects()
	if err1 != nil {
		return errors.Convert(err1)
	}
	err2 := commitIter.ForEach(func(commit *object.Commit) error {
		select {
		case <-subtaskCtx.GetContext().Done():
			return subtaskCtx.GetContext().Err()
		default:
		}
		commitSha := commit.Hash.String()
		r.logger.Debug("process commit: %s", commitSha)
		c := &code.Commit{
			Sha:     commitSha,
			Message: commit.Message,
		}

		c.AuthorName = commit.Author.Name
		c.AuthorEmail = commit.Author.Email
		c.AuthorId = commit.Author.Email
		c.AuthoredDate = commit.Author.When

		c.CommitterName = commit.Committer.Name
		c.CommitterEmail = commit.Committer.Email
		c.CommitterId = commit.Committer.Email
		c.CommittedDate = commit.Committer.When

		err1 := r.storeParentCommits(commitSha, commit)
		if err1 != nil {
			return err1
		}
		var parent *object.Commit
		var errParent error
		if commit.NumParents() > 0 {
			parents := commit.Parents()
			parent, errParent = parents.Next()
			if errParent != nil {
				return errParent
			}
		}
		stats, err := r.getDiffComparedToParent(c.Sha, commit, parent, componentMap)
		if err != nil {
			return err
		}
		for _, file := range stats {
			c.Additions += file.Addition
			c.Deletions += file.Deletion
		}
		err = r.store.Commits(c)
		if err != nil {
			return err
		}
		repoCommit := &code.RepoCommit{
			RepoId:    r.id,
			CommitSha: c.Sha,
		}
		err = r.store.RepoCommits(repoCommit)
		if err != nil {
			return err
		}
		subtaskCtx.IncProgress(1)
		return nil
	})
	return errors.Convert(err2)
}

func (r *GitRepo) storeParentCommits(commitSha string, commit *object.Commit) errors.Error {
	var commitParents []*code.CommitParent
	var parents = commit.Parents()
	err := parents.ForEach(func(parent *object.Commit) error {
		commitParents = append(commitParents, &code.CommitParent{
			CommitSha:       commitSha,
			ParentCommitSha: parent.ID().String(),
		})
		return nil
	})
	if err != nil {
		return errors.Convert(err)
	}
	return r.store.CommitParents(commitParents)
}

func (r *GitRepo) getDiffComparedToParent(commitSha string, commit *object.Commit, parent *object.Commit, componentMap map[string]*regexp.Regexp) (object.FileStats, errors.Error) {
	var err error
	var parentTree, tree *object.Tree
	if parent != nil {
		parentTree, err = parent.Tree()
	}
	if err != nil {
		return nil, errors.Convert(err)
	}
	tree, err = commit.Tree()
	if err != nil {
		return nil, errors.Convert(err)
	}

	diff, err := object.DiffTree(parentTree, tree)
	if err != nil {
		return nil, errors.Convert(err)
	}
	cfg := config.GetConfig()
	skipCommitFiles := cfg.GetBool(SkipCommitFiles)
	if !skipCommitFiles {
		err = r.storeCommitFilesFromDiff(commitSha, &diff, componentMap)
		if err != nil {
			return nil, errors.Convert(err)
		}
	}

	patch, err := diff.Patch()
	if err != nil {
		return nil, errors.Convert(err)
	}
	return patch.Stats(), nil
}

func (r *GitRepo) storeCommitFilesFromDiff(commitSha string, changes *object.Changes, componentMap map[string]*regexp.Regexp) errors.Error {
	patch, err := changes.Patch()
	if err != nil {
		return errors.Convert(err)
	}
	for _, filePatch := range patch.FilePatches() {
		fromFile, toFile := filePatch.Files()
		var filePath string
		if toFile == nil {
			filePath = fromFile.Path()
		} else {
			filePath = toFile.Path()
		}

		// With some long path,the varchar(255) was not enough both ID and file_path
		// So we use the hash to compress the path in ID and add length of file_path.
		// Use commitSha and the sha256 of FilePath to create id
		shaFilePath := sha256.New()
		shaFilePath.Write([]byte(filePath))
		commitFileId := commitSha + ":" + hex.EncodeToString(shaFilePath.Sum(nil))
		commitFile := code.CommitFile{
			CommitSha: commitSha,
			FilePath:  filePath,
		}
		commitFile.Id = commitFileId
		// iterate over the chunks
		for _, chunk := range filePatch.Chunks() {
			// iterate over the chunks, get addition lines and deletion lines
			if chunk.Type() == diff.Add {
				commitFile.Additions += lineCount(chunk.Content())
			} else if chunk.Type() == diff.Delete {
				commitFile.Deletions += lineCount(chunk.Content())
			}
		}
		err = r.store.CommitFiles(&commitFile)
		if err != nil {
			r.logger.Error(err, "CommitFiles error")
		}

		// load component info
		commitFileComponent := code.CommitFileComponent{
			CommitFileId: commitFileId,
		}
		for component, reg := range componentMap {
			if reg.MatchString(commitFile.FilePath) {
				commitFileComponent.ComponentName = component
				break
			}
		}
		if commitFileComponent.ComponentName == "" {
			commitFileComponent.ComponentName = "Default"
		}

		err = r.store.CommitFileComponents(&commitFileComponent)
		if err != nil {
			r.logger.Error(err, "CommitFileComponents error")
		}
	}
	return nil
}

// Collecti Snapshot blame data of HEAD commit
func (r *GitRepo) CollectSnapshot(subtaskCtx plugin.SubTaskContext) errors.Error {
	var repo = r.repo
	head, err := repo.Head()
	if err != nil {
		return errors.Convert(err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return errors.Convert(err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return errors.Convert(err)
	}
	// get all files in the tree
	var files []*object.File
	var fileIter = tree.Files()
	err = fileIter.ForEach(func(file *object.File) error {
		select {
		case <-subtaskCtx.GetContext().Done():
			return subtaskCtx.GetContext().Err()
		default:
		}
		files = append(files, file)
		return nil
	})
	if err != nil {
		return errors.Convert(err)
	}
	// get the blame of each file
	for _, file := range files {
		select {
		case <-subtaskCtx.GetContext().Done():
			return errors.Convert(subtaskCtx.GetContext().Err())
		default:
		}
		blame, err := git.Blame(commit, file.Name)
		if err != nil {
			return errors.Convert(err)
		}
		for lineNo, line := range blame.Lines {
			if line != nil {
				commitLine := &code.RepoSnapshot{
					RepoId:    r.id,
					CommitSha: commit.Hash.String(),
					FilePath:  file.Name,
					LineNo:    lineNo + 1,
				}
				err = r.store.RepoSnapshot(commitLine)
				if err != nil {
					return errors.Convert(err)
				}
			}
		}
	}
	r.logger.Info("line change collect success")
	return nil
}

// CollectDiffLine get line diff data from a specific branch
func (r *GitRepo) CollectDiffLine(subtaskCtx plugin.SubTaskContext) errors.Error {
	//Using this subtask, we can get every line change in every commit, tracing back from HEAD to the first commit
	repo := r.repo
	//step 1. get the reverse commit list
	commitList := make([]object.Commit, 0)
	//get currently head commitsha, dafault is master branch
	// check branch, if not master, checkout to branch's head
	commitOid, err1 := repo.Head()
	if err1 != nil && err1.Error() != TypeNotMatchError {
		return errors.Convert(err1)
	}
	//get head commit object and add into commitList
	commit, err1 := repo.CommitObject(commitOid.Hash())
	if err1 != nil && err1.Error() != TypeNotMatchError {
		return errors.Convert(err1)
	}
	commitList = append(commitList, *commit)
	// if current head has parents, get parent commitsha
	for commit != nil && commit.NumParents() > 0 {
		commit, err1 := commit.Parent(0)
		if err1 != nil && err1.Error() != TypeNotMatchError {
			return errors.Convert(err1)
		}
		commitList = append(commitList, *commit)
	}
	// reverse commitList
	for i, j := 0, len(commitList)-1; i < j; i, j = i+1, j-1 {
		commitList[i], commitList[j] = commitList[j], commitList[i]
	}
	//step 2. get the diff of each commit
	// for each commit, get the diff
	for _, curcommit := range commitList {
		var parentCommit *object.Commit
		var parentTree, tree *object.Tree
		tree, err := curcommit.Tree()
		if err != nil {
			return errors.Convert(err)
		}
		if curcommit.NumParents() > 0 {
			parentCommit, err = curcommit.Parent(0)
			if err != nil {
				return errors.Convert(err)
			}
			parentTree, err = parentCommit.Tree()
		}
		changes, err := object.DiffTree(parentTree, tree)
		if err != nil {
			return errors.Convert(err)
		}

		for _, fileDiff := range changes {
			fromFile, toFile, err := fileDiff.Files()
			if err != nil {
				return errors.Convert(err)
			}
			var filePath string
			var prevBlame *git.BlameResult
			if fromFile != nil {
				prevBlame, err = git.Blame(parentCommit, filePath)
				if err != nil {
					return errors.Convert(err)
				}
			}
			if toFile != nil {
				filePath = toFile.Name
			} else {
				filePath = fromFile.Name
			}

			filePatch, err := fileDiff.Patch()
			if err != nil {
				return errors.Convert(err)
			}
			filePatches := filePatch.FilePatches()
			for _, fp := range filePatches {
				var hunkGen = newHunksGenerator(fp.Chunks(), 0)
				hunks := hunkGen.Generate()
				for hunkNum, hunk := range hunks {
					for offset, line := range hunk.ops {
						commitLineChange := &code.CommitLineChange{}
						commitLineChange.CommitSha = curcommit.Hash.String()
						if line.t == diff.Equal {
							continue
						} else if line.t == diff.Add {
							commitLineChange.ChangedType = "add"
						} else if line.t == diff.Delete {
							commitLineChange.ChangedType = "delete"
						}
						commitLineChange.LineNoNew = hunk.toLine + offset
						commitLineChange.LineNoOld = hunk.fromLine + offset
						commitLineChange.OldFilePath = fromFile.Name
						commitLineChange.NewFilePath = toFile.Name
						commitLineChange.HunkNum = hunkNum
						commitLineChange.Id = curcommit.Hash.String() + ":" + filePath + ":" + strconv.Itoa(hunk.fromLine+offset) + ":" + strconv.Itoa(hunk.toLine+offset)
						if prevBlame != nil {
							lineBlame := prevBlame.Lines[hunk.fromLine+offset]
							if lineBlame != nil {
								commitLineChange.PrevCommit = lineBlame.Hash.String()
							}
						}
						err = r.store.CommitLineChange(commitLineChange)
						if err != nil {
							return errors.Convert(err)
						}
					}
				}
			}
		}
	}
	r.logger.Info("line change collect success")
	return nil
}

func lineCount(content string) int {
	count := 0
	for _, c := range content {
		if c == '\n' {
			count++
		}
	}
	return count
}

type hunksGenerator struct {
	fromLine, toLine            int
	ctxLines                    int
	chunks                      []diff.Chunk
	current                     *hunk
	hunks                       []*hunk
	beforeContext, afterContext []string
}

func newHunksGenerator(chunks []diff.Chunk, ctxLines int) *hunksGenerator {
	return &hunksGenerator{
		chunks:   chunks,
		ctxLines: ctxLines,
	}
}

func (g *hunksGenerator) Generate() []*hunk {
	for i, chunk := range g.chunks {
		lines := splitLines(chunk.Content())
		nLines := len(lines)

		switch chunk.Type() {
		case diff.Equal:
			g.fromLine += nLines
			g.toLine += nLines
			g.processEqualsLines(lines, i)
		case diff.Delete:
			if nLines != 0 {
				g.fromLine++
			}

			g.processHunk(i, chunk.Type())
			g.fromLine += nLines - 1
			g.current.AddOp(chunk.Type(), lines...)
		case diff.Add:
			if nLines != 0 {
				g.toLine++
			}
			g.processHunk(i, chunk.Type())
			g.toLine += nLines - 1
			g.current.AddOp(chunk.Type(), lines...)
		}

		if i == len(g.chunks)-1 && g.current != nil {
			g.hunks = append(g.hunks, g.current)
		}
	}

	return g.hunks
}

func (g *hunksGenerator) processHunk(i int, op diff.Operation) {
	if g.current != nil {
		return
	}

	var ctxPrefix string
	linesBefore := len(g.beforeContext)
	if linesBefore > g.ctxLines {
		ctxPrefix = g.beforeContext[linesBefore-g.ctxLines-1]
		g.beforeContext = g.beforeContext[linesBefore-g.ctxLines:]
		linesBefore = g.ctxLines
	}

	g.current = &hunk{ctxPrefix: strings.TrimSuffix(ctxPrefix, "\n")}
	g.current.AddOp(diff.Equal, g.beforeContext...)

	switch op {
	case diff.Delete:
		g.current.fromLine, g.current.toLine =
			g.addLineNumbers(g.fromLine, g.toLine, linesBefore, i, diff.Add)
	case diff.Add:
		g.current.toLine, g.current.fromLine =
			g.addLineNumbers(g.toLine, g.fromLine, linesBefore, i, diff.Delete)
	}

	g.beforeContext = nil
}

// addLineNumbers obtains the line numbers in a new chunk.
func (g *hunksGenerator) addLineNumbers(la, lb int, linesBefore int, i int, op diff.Operation) (cla, clb int) {
	cla = la - linesBefore
	// we need to search for a reference for the next diff
	switch {
	case linesBefore != 0 && g.ctxLines != 0:
		if lb > g.ctxLines {
			clb = lb - g.ctxLines + 1
		} else {
			clb = 1
		}
	case g.ctxLines == 0:
		clb = lb
	case i != len(g.chunks)-1:
		next := g.chunks[i+1]
		if next.Type() == op || next.Type() == diff.Equal {
			// this diff will be into this chunk
			clb = lb + 1
		}
	}

	return
}

func (g *hunksGenerator) processEqualsLines(ls []string, i int) {
	if g.current == nil {
		g.beforeContext = append(g.beforeContext, ls...)
		return
	}

	g.afterContext = append(g.afterContext, ls...)
	if len(g.afterContext) <= g.ctxLines*2 && i != len(g.chunks)-1 {
		g.current.AddOp(diff.Equal, g.afterContext...)
		g.afterContext = nil
	} else {
		ctxLines := g.ctxLines
		if ctxLines > len(g.afterContext) {
			ctxLines = len(g.afterContext)
		}
		g.current.AddOp(diff.Equal, g.afterContext[:ctxLines]...)
		g.hunks = append(g.hunks, g.current)

		g.current = nil
		g.beforeContext = g.afterContext[ctxLines:]
		g.afterContext = nil
	}
}

func splitLines(s string) []string {
	out := splitLinesRegexp.FindAllString(s, -1)
	if out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

type hunk struct {
	fromLine int
	toLine   int

	fromCount int
	toCount   int

	ctxPrefix string
	ops       []*op
}

func (h *hunk) AddOp(t diff.Operation, ss ...string) {
	n := len(ss)
	switch t {
	case diff.Add:
		h.toCount += n
	case diff.Delete:
		h.fromCount += n
	case diff.Equal:
		h.toCount += n
		h.fromCount += n
	}

	for _, s := range ss {
		h.ops = append(h.ops, &op{s, t})
	}
}

type op struct {
	text string
	t    diff.Operation
}

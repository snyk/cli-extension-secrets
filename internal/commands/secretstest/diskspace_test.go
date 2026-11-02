package secretstest

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGitHugeRepoScript pretends the repository is far larger than any disk and makes every other command fail.
const fakeGitHugeRepoScript = `case "$*" in
*count-objects*) printf 'size: 0\nsize-pack: 9999999999999\n' ;;
*) echo "fatal: some failure" >&2; exit 128 ;;
esac`

// fakeGitTinyRepoScript pretends the repository is tiny and makes every other command fail.
const fakeGitTinyRepoScript = `case "$*" in
*count-objects*) printf 'size: 1\nsize-pack: 1\n' ;;
*) echo "fatal: some failure" >&2; exit 128 ;;
esac`

func TestParseCountObjects(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    uint64
		wantErr bool
	}{
		{
			name: "full output",
			in:   "count: 299\nsize: 2536\nin-pack: 893\npacks: 1\nsize-pack: 400\nprune-packable: 0\ngarbage: 0\nsize-garbage: 0\n",
			want: (2536 + 400) * 1024,
		},
		{name: "only packs", in: "count: 0\nsize: 0\nsize-pack: 10\n", want: 10 * 1024},
		{name: "garbage is not counted", in: "size: 1\nsize-pack: 1\nsize-garbage: 999\n", want: 2 * 1024},
		{name: "empty repository", in: "size: 0\nsize-pack: 0\n", want: 0},
		{name: "no size information", in: "count: 1\n", wantErr: true},
		{name: "empty output", in: "", wantErr: true},
		{name: "not a number", in: "size: lots\nsize-pack: 1\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCountObjects(tt.in)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAvailableBytes(t *testing.T) {
	free, err := availableBytes(t.TempDir())

	require.NoError(t, err)
	assert.Positive(t, free)
}

func TestAvailableBytes_MissingDirectory(t *testing.T) {
	_, err := availableBytes(t.TempDir() + "/does-not-exist")

	require.Error(t, err)
}

func TestEstimateRepoSize(t *testing.T) {
	src := newTestRepo(t, 2)
	// Git for Windows reports loose objects as 0 KiB, because it has no block count to measure them with.
	// Packed objects are sized by file length on every platform.
	gitOutput(t, src, "repack", "-a", "-d", "--quiet")

	got, err := estimateRepoSize(context.Background(), src)

	require.NoError(t, err)
	assert.Positive(t, got)
}

func TestDiagnoseDiskSpace(t *testing.T) {
	cause := errors.New("git clone failed: exit status 128")

	t.Run("nil error stays nil", func(t *testing.T) {
		require.NoError(t, diagnoseDiskSpace(context.Background(), nil, t.TempDir(), t.TempDir()))
	})

	t.Run("not enough free space is reported", func(t *testing.T) {
		useFakeGit(t, fakeGitHugeRepoScript)

		got := diagnoseDiskSpace(context.Background(), cause, t.TempDir(), t.TempDir())

		require.ErrorIs(t, got, ErrInsufficientDiskSpace)
		require.ErrorIs(t, got, cause)
	})

	t.Run("enough free space keeps the original error", func(t *testing.T) {
		useFakeGit(t, fakeGitTinyRepoScript)

		got := diagnoseDiskSpace(context.Background(), cause, t.TempDir(), t.TempDir())

		assert.Equal(t, cause, got)
	})

	t.Run("size estimate failing keeps the original error", func(t *testing.T) {
		useFakeGit(t, `echo "fatal: not a git repository" >&2; exit 128`)

		got := diagnoseDiskSpace(context.Background(), cause, t.TempDir(), t.TempDir())

		assert.Equal(t, cause, got)
	})

	t.Run("free space failing keeps the original error", func(t *testing.T) {
		useFakeGit(t, fakeGitHugeRepoScript)

		got := diagnoseDiskSpace(context.Background(), cause, t.TempDir(), t.TempDir()+"/does-not-exist")

		assert.Equal(t, cause, got)
	})

	t.Run("canceled context is not a disk problem", func(t *testing.T) {
		useFakeGit(t, fakeGitHugeRepoScript)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		got := diagnoseDiskSpace(ctx, cause, t.TempDir(), t.TempDir())

		assert.Equal(t, cause, got)
	})

	t.Run("missing git is not a disk problem", func(t *testing.T) {
		gitMissing := errors.Join(ErrGitNotFound, errors.New("lookup failed"))

		got := diagnoseDiskSpace(context.Background(), gitMissing, t.TempDir(), t.TempDir())

		assert.Equal(t, gitMissing, got)
	})
}

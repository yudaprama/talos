package sqlutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeref(t *testing.T) {
	t.Parallel()

	t.Run("non-nil string pointer", func(t *testing.T) {
		t.Parallel()
		s := "hello"
		assert.Equal(t, "hello", Deref(&s))
	})

	t.Run("nil string pointer", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, Deref((*string)(nil)))
	})

	t.Run("non-nil int pointer", func(t *testing.T) {
		t.Parallel()
		i := 42
		assert.Equal(t, 42, Deref(&i))
	})

	t.Run("nil int pointer", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 0, Deref((*int)(nil)))
	})

	t.Run("nil time pointer", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, time.Time{}, Deref((*time.Time)(nil)))
	})
}

func TestPtrOrNil(t *testing.T) {
	t.Parallel()

	t.Run("non-zero string returns pointer", func(t *testing.T) {
		t.Parallel()
		p := PtrOrNil("hello")
		assert.NotNil(t, p)
		assert.Equal(t, "hello", *p)
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, PtrOrNil(""))
	})

	t.Run("non-zero int returns pointer", func(t *testing.T) {
		t.Parallel()
		p := PtrOrNil(42)
		assert.NotNil(t, p)
		assert.Equal(t, 42, *p)
	})

	t.Run("zero int returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, PtrOrNil(0))
	})

	t.Run("non-zero int64 returns pointer", func(t *testing.T) {
		t.Parallel()
		p := PtrOrNil(int64(100))
		assert.NotNil(t, p)
		assert.Equal(t, int64(100), *p)
	})

	t.Run("false bool returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, PtrOrNil(false))
	})

	t.Run("true bool returns pointer", func(t *testing.T) {
		t.Parallel()
		p := PtrOrNil(true)
		assert.NotNil(t, p)
		assert.True(t, *p)
	})
}

func TestNonNilSlice(t *testing.T) {
	t.Parallel()

	t.Run("nil slice returns empty non-nil slice", func(t *testing.T) {
		t.Parallel()
		result := NonNilSlice[string](nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("empty slice returns same slice", func(t *testing.T) {
		t.Parallel()
		input := []string{}
		result := NonNilSlice(input)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("non-empty slice returns same slice", func(t *testing.T) {
		t.Parallel()
		input := []string{"a", "b"}
		result := NonNilSlice(input)
		assert.Equal(t, []string{"a", "b"}, result)
	})

	t.Run("nil int slice returns empty non-nil slice", func(t *testing.T) {
		t.Parallel()
		result := NonNilSlice[int](nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})
}

// reviewed - @aeneasr - 2026-03-26

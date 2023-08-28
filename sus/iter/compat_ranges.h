// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <iterator>
#include <ranges>

#include "sus/iter/__private/iterator_end.h"
#include "sus/iter/__private/range_begin.h"
#include "sus/iter/iterator.h"
#include "sus/macros/__private/compiler_bugs.h"
#include "sus/macros/lifetimebound.h"
#include "sus/mem/move.h"
#include "sus/num/transmogrify.h"
#include "sus/num/unsigned_integer.h"
#include "sus/option/option.h"

namespace sus::iter {

template <class R, class B, class E, class ItemT>
class IteratorOverRange;

/// Constructs an [`Iterator`](sus-iter-Iterator.html) from a
/// [`std::ranges::input_range`](https://en.cppreference.com/w/cpp/ranges/input_range).
///
/// If the input is an lvalue reference, the `Iterator` will also
/// iterate over references to the range's values. If the input is const, the
/// `Iterator` will iterate over const references. To iterate over values
/// instead, use [`Iterator::cloned`](sus-iter-IteratorBase.html#method.cloned) or
/// [`Iterator::copied`](sus-iter-IteratorBase.html#method.copied).
///
/// If the input is an rvalue refernce, the `Iterator` will iterate over the
/// moved items from the range.
///
/// If the input range's iterators satisfy `std::ranges::bidiectional_iterator`,
/// then the output `Iterator` will be a `DoubleEndedIterator`.
///
/// If the end type (aka `std::ranges::sentinel_t`) of the input range satisfies
/// `std::ranges::std::sized_sentinel_for<end type, begin type>`, then the
/// output `Iterator` will be an `ExactSizeIterator`.
///
/// # Examples
/// Iterates over references of a vector, copying and summing:
/// ```
/// const auto v = std::vector<i32>({1, 2, 3});
/// sus::check(sus::iter::from_range(v).copied().sum() == 1 + 2 + 3);
/// ```
///
/// Consumes a vector and iterates over its values, not as references.
/// ```
/// auto v = std::vector<i32>({1, 2, 3});
/// sus::check(sus::iter::from_range(sus::move(v)).sum() == 1 + 2 + 3);
/// ```
template <class R>
  requires(std::ranges::input_range<R>)
auto from_range(R&& r) noexcept {
  if constexpr (std::is_lvalue_reference_v<R&&>) {
    using B = decltype(std::declval<R&>().begin());
    using E = decltype(std::declval<R&>().end());
    using Item = typename std::iterator_traits<B>::reference;
    if constexpr (sus::mem::relocate_by_memcpy<B> &&
                  sus::mem::relocate_by_memcpy<E>)
      return IteratorOverRange<R, B, E, Item>(r);
    else
      return IteratorOverRange<R, B, E, Item>(r).box();
  } else {
    using B = decltype(std::make_move_iterator(std::declval<R&>().begin()));
    using E = decltype(std::make_move_iterator(std::declval<R&>().end()));
    using Item = typename std::iterator_traits<B>::value_type;
    return IteratorOverRange<R, B, E, Item>(r);
  }
}

template <class R, class B, class E, class ItemT>
class IteratorOverRange final
    : public IteratorBase<IteratorOverRange<R, B, E, ItemT>, ItemT> {
 public:
  using Item = ItemT;

  // sus::mem::Move but not Copy.
  IteratorOverRange(IteratorOverRange&&) = default;
  IteratorOverRange& operator=(IteratorOverRange&&) = default;

  /// sus::mem::Clone trait.
  IteratorOverRange clone() const { return IteratorOverRange(begin_, end_); }

  /// sus::iter::Iterator trait.
  Option<Item> next() noexcept {
    Option<Item> out;
    if (begin_ == end_) return out;
    out.insert(*begin_);
    ++begin_;
    return out;
  }
  /// sus::iter::Iterator trait.
  SizeHint size_hint() const noexcept {
    if constexpr (std::sized_sentinel_for<B, E>) {
      const auto rem = exact_size_hint();
      return {rem, sus::some(rem)};
    } else {
      return {0u, sus::none()};
    }
  }
  /// sus::iter::DoubleEndedIterator trait.
  Option<Item> next_back() noexcept
    requires(std::ranges::bidirectional_range<R>)
  {
    Option<Item> out;
    if (begin_ == end_) return out;
    --end_;
    out.insert(*end_);
    return out;
  }
  /// sus::iter::ExactSizeIterator trait.
  usize exact_size_hint() const noexcept
    requires(std::sized_sentinel_for<B, E>)
  {
    // SAFETY: `end_ > begin_` so the value is not negative and offsets in a
    // collection are always in the range of `isize`, so the value is
    // representable in `usize`.
    return usize::try_from(end_ - begin_)
        .unwrap_unchecked(::sus::marker::unsafe_fn);
  }

  /// sus::iter::TrustedLen trait.
  /// #[doc.hidden]
  constexpr ::sus::iter::__private::TrustedLenMarker trusted_len()
      const noexcept
    requires(std::sized_sentinel_for<B, E>)
  {
    return {};
  }

  // TODO: If std::random_access_range<B> then implement more efficient nth(),
  // nth_back().

 private:
  friend auto sus::iter::from_range<R>(R&&) noexcept;

  IteratorOverRange(R& r sus_lifetimebound) noexcept
      : begin_(std::ranges::begin(r)), end_(std::ranges::end(r)) {}

  IteratorOverRange(B begin, E end) : begin_(begin), end_(end) {}

  B begin_;
  E end_;

  sus_class_trivially_relocatable_if_types(::sus::marker::unsafe_fn,
                                           decltype(begin_), decltype(end_));
};

/// Support for use of a sus::Iterator as a `std::ranges::input_range` in the
/// std::ranges library.
///
/// This type is returned from `Iterator::range()`.
template <class Iter>
class IteratorRange {
  using Item = typename Iter::Item;

 public:
  constexpr auto begin() noexcept {
    return __private::RangeBegin<IteratorRange, Item>(this);
  }
  constexpr auto end() noexcept { return __private::IteratorEnd(); }

 private:
  template <class U, class V>
  friend class IteratorBase;

  friend class __private::RangeBegin<IteratorRange, Item>;

  constexpr IteratorRange(Iter&& it) noexcept : it_(::sus::move(it)) { step(); }

  constexpr void step() noexcept { item_ = it_.next(); }

  Iter it_;
  Option<Item> item_;
};

}  // namespace sus::iter

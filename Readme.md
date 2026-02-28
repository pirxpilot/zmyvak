[![NPM version][npm-image]][npm-url]
[![Build Status][build-image]][build-url]
[![Dependency Status][deps-image]][deps-url]

# zmyvak

Simple HTML sanitizer that removes dangerous tags and attributes to prevent XSS attacks.
It strips elements like `<script>`, `<iframe>`, `<style>`, and others, as well as event
handler attributes (e.g. `onclick`, `onmouseover`) and attributes that can carry
`javascript:` or `vbscript:` payloads.

Based on [simple-sanitize-html]

## Install

```sh
$ npm install --save zmyvak
```

## Usage

```js
import sanitizeHTML from 'zmyvak';

// Plain text passes through unchanged
sanitizeHTML('Hello, world!');
// => 'Hello, world!'

// Safe tags and attributes are preserved
sanitizeHTML('<p class="intro">Hello, <strong>world</strong>!</p>');
// => '<p class="intro">Hello, <strong>world</strong>!</p>'

// Dangerous tags are removed entirely
sanitizeHTML('<div>safe content</div><script>alert("xss")</script>');
// => '<div>safe content</div>'

// Event handler attributes are stripped
sanitizeHTML('<a onmouseover="alert(document.cookie)">click me</a>');
// => '<a>click me</a>'

// javascript: URLs are removed from attributes
sanitizeHTML('<a href="javascript:alert(1)">click me</a>');
// => '<a>click me</a>'

// Custom bad tags and attributes can be provided
sanitizeHTML('<div>text</div><marquee>annoying</marquee>', {
  badTags: new Set(['MARQUEE'])
});
// => '<div>text</div>'
```

## License

ICS © [Damian Krzeminski](https://pirxpilot.me)

[simple-sanitize-html]: https://www.npmjs.com/package/simple-sanitize-html

[npm-image]: https://img.shields.io/npm/v/zmyvak
[npm-url]: https://npmjs.org/package/zmyvak

[build-url]: https://github.com/pirxpilot/zmyvak/actions/workflows/check.yaml
[build-image]: https://img.shields.io/github/actions/workflow/status/pirxpilot/zmyvak/check.yaml?branch=main

[deps-image]: https://img.shields.io/librariesio/release/npm/zmyvak
[deps-url]: https://libraries.io/npm/zmyvak

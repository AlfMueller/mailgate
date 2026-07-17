# Translating MailGate

MailGate uses English as its source language. German is the first additional translation and
lives in `app/locale/de/LC_MESSAGES/django.po`. Translation changes are deliberately plain-text
Git changes so contributors can propose them through an ordinary GitHub pull request without
special accounts or hosted translation services.

## Improve the German translation

1. Edit only the `msgstr` values in `app/locale/de/LC_MESSAGES/django.po`.
2. Keep interpolation markers such as `{challenge}` and `%(name)s` unchanged.
3. Use synthetic examples only. Never include credentials, private addresses, message content,
   API tokens, or other personal data.
4. Compile and test the catalog:

   ```text
   python app/compile_translations.py
   python app/manage.py test tests --settings=mailgate.test_settings
   ```

The compiled `.mo` file is generated during the container build and is intentionally ignored by
Git. The small repository compiler supports the simple Django catalog format used here and keeps
the production image free of gettext build tooling. It rejects mismatched interpolation markers,
and the automated tests require every marked literal in Python and templates to exist in the German
catalog. Fuzzy entries are deliberately not compiled.

## Add another language

1. Copy the German catalog structure to `app/locale/<language-code>/LC_MESSAGES/django.po`.
2. Preserve each English `msgid` and translate its `msgstr`.
3. Add the language code and native-language label to `LANGUAGES` in
   `app/mailgate/settings.py`.
4. Add UI tests for language selection and at least the public About page.
5. Run the compiler, tests, formatter, and lint checks.

Machine-facing API field names, state values, error codes, audit action names, and security signal
identifiers stay in stable English. Only human-facing text is localized.

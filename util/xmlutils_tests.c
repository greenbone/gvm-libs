/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "xmlutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <glib/gstdio.h>

static gchar *
write_temp_xml (const char *xml)
{
  gchar *path = NULL;
  GError *err = NULL;
  if (!g_file_open_tmp ("xmliterXXXXXX", &path, NULL))
    return NULL;
  if (!g_file_set_contents (path, xml, -1, &err))
    {
      if (path)
        g_unlink (path);
      g_clear_error (&err);
      g_free (path);
      return NULL;
    }
  return path;
}

Describe (xmlutils);
BeforeEach (xmlutils)
{
}
AfterEach (xmlutils)
{
}

/* parse_entity */

Ensure (xmlutils, parse_entity_parses_simple_xml)
{
  entity_t entity, b;
  const gchar *xml;

  xml = "<a><b>1</b></a>";

  assert_that (parse_entity (xml, &entity), is_equal_to (0));

  assert_that (entity_name (entity), is_equal_to_string ("a"));

  b = entity_child (entity, "b");
  assert_that (entity_name (b), is_equal_to_string ("b"));

  assert_that (entity_text (b), is_equal_to_string ("1"));
}

Ensure (xmlutils, parse_entity_parses_xml_with_attributes)
{
  entity_t entity, b;
  const gchar *xml;

  xml = "<a><b ba1='test'>1</b></a>";

  assert_that (parse_entity (xml, &entity), is_equal_to (0));

  b = entity_child (entity, "b");

  assert_that (entity_attribute (b, "ba1"), is_equal_to_string ("test"));
}

Ensure (xmlutils, parse_entity_handles_declaration)
{
  entity_t entity, b;
  const gchar *xml;

  xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a><b ba1='test'>1</b></a>";

  assert_that (parse_entity (xml, &entity), is_equal_to (0));

  assert_that (entity_name (entity), is_equal_to_string ("a"));

  b = entity_child (entity, "b");
  assert_that (entity_name (b), is_equal_to_string ("b"));

  assert_that (entity_text (b), is_equal_to_string ("1"));
}

Ensure (xmlutils, parse_entity_handles_namespace)
{
  entity_t entity, b;
  const gchar *xml;

  xml =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a><n:b ba1='test'>1</n:b></a>";

  assert_that (parse_entity (xml, &entity), is_equal_to (0));

  assert_that (entity_name (entity), is_equal_to_string ("a"));

  b = entity_child (entity, "n:b");
  assert_that (entity_name (b), is_equal_to_string ("n:b"));

  assert_that (entity_text (b), is_equal_to_string ("1"));
}

Ensure (xmlutils, parse_entity_oval_timestamp)
{
  gchar *generator_name;
  entity_t generator, timestamp, entity;
  const gchar *xml;

  xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<oval_definitions "
        "xsi:schemaLocation=\"http://oval.mitre.org/XMLSchema/"
        "oval-definitions-5 oval-definitions-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux "
        "linux-definitions-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-definitions-5#windows "
        "windows-definitions-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent "
        "independent-definitions-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix "
        "unix-definitions-schema.xsd\" "
        "xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\" "
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
        "xmlns:oval=\"http://oval.mitre.org/XMLSchema/oval-common-5\" "
        "xmlns:oval-def=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\">"
        "  <generator>"
        "    <oval:product_name>The OVAL Repository</oval:product_name>"
        "    <oval:schema_version>5.10</oval:schema_version>"
        "    <oval:timestamp>2015-08-20T10:09:07.183-04:00</oval:timestamp>"
        "  </generator>"
        "</oval_definitions>";

  assert_that (parse_entity (xml, &entity), is_equal_to (0));

  assert_that (entity_name (entity), is_equal_to_string ("oval_definitions"));
  generator_name = g_strdup ("generator");
  generator = entity_child (entity, generator_name);
  g_free (generator_name);
  assert_that (generator, is_not_null);
  timestamp = entity_child (generator, "oval:timestamp");
  assert_that (timestamp, is_not_null);
  assert_that (entity_text (timestamp),
               is_equal_to_string ("2015-08-20T10:09:07.183-04:00"));
}

/* next_entities. */

Ensure (xmlutils, next_entities_handles_multiple_children)
{
  entity_t entity, child;
  entities_t children;
  const gchar *xml;

  xml = "<top><a>1</a><b></b><c>3</c></top>";

  assert_that (parse_entity (xml, &entity), is_equal_to (0));

  assert_that (entity_name (entity), is_equal_to_string ("top"));

  children = entity->entities;

  child = first_entity (children);
  assert_that (child, is_not_null);
  assert_that (entity_name (child), is_equal_to_string ("a"));
  assert_that (entity_text (child), is_equal_to_string ("1"));
  children = next_entities (children);

  child = first_entity (children);
  assert_that (child, is_not_null);
  assert_that (entity_name (child), is_equal_to_string ("b"));
  assert_that (entity_text (child), is_equal_to_string (""));
  children = next_entities (children);

  child = first_entity (children);
  assert_that (child, is_not_null);
  assert_that (entity_name (child), is_equal_to_string ("c"));
  assert_that (entity_text (child), is_equal_to_string ("3"));
  children = next_entities (children);
}

/* parse_element */

Ensure (xmlutils, parse_element_parses_simple_xml)
{
  element_t element, b;
  const gchar *xml;

  xml = "<a><b>1</b></a>";

  assert_that (parse_element (xml, &element), is_equal_to (0));

  assert_that (element_name (element), is_equal_to_string ("a"));

  b = element_child (element, "b");
  assert_that (element_name (b), is_equal_to_string ("b"));

  assert_that (element_text (b), is_equal_to_string ("1"));
}

Ensure (xmlutils, parse_element_parses_xml_with_attributes)
{
  element_t element, b;
  const gchar *xml;

  xml = "<a><b ba1='test'>1</b></a>";

  assert_that (parse_element (xml, &element), is_equal_to (0));

  b = element_child (element, "b");

  assert_that (element_attribute (b, "ba1"), is_equal_to_string ("test"));
}

Ensure (xmlutils, parse_element_handles_declaration)
{
  element_t element, b;
  const gchar *xml;

  xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a><b ba1='test'>1</b></a>";

  assert_that (parse_element (xml, &element), is_equal_to (0));

  assert_that (element_name (element), is_equal_to_string ("a"));

  b = element_child (element, "b");
  assert_that (element_name (b), is_equal_to_string ("b"));

  assert_that (element_text (b), is_equal_to_string ("1"));
}

Ensure (xmlutils, parse_element_handles_namespace)
{
  element_t element, b;
  const gchar *xml;

  xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a><n:b ba1='test' "
        "n2:ba2='test2'>1</n:b></a>";

  assert_that (parse_element (xml, &element), is_equal_to (0));

  assert_that (element_name (element), is_equal_to_string ("a"));

  b = element_child (element, "n:b");
  assert_that (element_name (b), is_equal_to_string ("n:b"));

  assert_that (element_text (b), is_equal_to_string ("1"));

  assert_that (element_attribute (b, "n2:ba2"), is_equal_to_string ("test2"));
}

Ensure (xmlutils, parse_element_oval_timestamp)
{
  gchar *generator_name;
  element_t generator, timestamp, element;
  const gchar *xml;

  xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<oval_definitions "
        "xsi:schemaLocation=\"http://oval.mitre.org/XMLSchema/"
        "oval-definitions-5 oval-definitions-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux "
        "linux-definitions-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-definitions-5#windows "
        "windows-definitions-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent "
        "independent-definitions-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd "
        "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix "
        "unix-definitions-schema.xsd\" "
        "xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\" "
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
        "xmlns:oval=\"http://oval.mitre.org/XMLSchema/oval-common-5\" "
        "xmlns:oval-def=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\">"
        "  <generator>"
        "    <oval:product_name>The OVAL Repository</oval:product_name>"
        "    <oval:schema_version>5.10</oval:schema_version>"
        "    <oval:timestamp>2015-08-20T10:09:07.183-04:00</oval:timestamp>"
        "  </generator>"
        "</oval_definitions>";

  assert_that (parse_element (xml, &element), is_equal_to (0));

  assert_that (element_name (element), is_equal_to_string ("oval_definitions"));
  generator_name = g_strdup ("generator");
  generator = element_child (element, generator_name);
  g_free (generator_name);
  assert_that (generator, is_not_null);
  timestamp = element_child (generator, "oval:timestamp");
  assert_that (timestamp, is_not_null);
  assert_that (element_text (timestamp),
               is_equal_to_string ("2015-08-20T10:09:07.183-04:00"));
}

Ensure (xmlutils, parse_element_item_metadata)
{
  element_t element, item, meta;
  const gchar *xml;

  xml = "<cpe-list>"
        "  <cpe-item "
        "name=\"cpe:/"
        "a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~\">"
        "    <title xml:lang=\"en-US\">$0.99 Kindle Books project $0.99 Kindle "
        "Books (aka com.kindle.books.for99) for android 6.0</title>"
        "    <references>"
        "      <reference "
        "href=\"https://play.google.com/store/apps/"
        "details?id=com.kindle.books.for99\">Product information</reference>"
        "      <reference "
        "href=\"https://docs.google.com/spreadsheets/d/"
        "1t5GXwjw82SyunALVJb2w0zi3FoLRIkfGPc7AMjRF0r4/"
        "edit?pli=1#gid=1053404143\">Government Advisory</reference>"
        "    </references>"
        "    <meta:item-metadata nvd-id=\"289692\" status=\"FINAL\" "
        "modification-date=\"2014-11-10T17:01:25.103Z\"/>"
        "  </cpe-item>"
        "</cpe-list>";

  assert_that (parse_element (xml, &element), is_equal_to (0));

  assert_that (element_name (element), is_equal_to_string ("cpe-list"));
  item = element_child (element, "cpe-item");
  assert_that (item, is_not_null);
  meta = element_child (item, "meta:item-metadata");
  assert_that (meta, is_not_null);
  assert_that (element_name (meta), is_equal_to_string ("meta:item-metadata"));
}

Ensure (xmlutils, parse_element_item_metadata_with_namespace)
{
  element_t element, item, meta;
  const gchar *xml;

  xml = "<cpe-list xmlns=\"http://cpe.mitre.org/dictionary/2.0\" "
        "xmlns:ns6=\"http://scap.nist.gov/schema/scap-core/0.1\" "
        "xmlns:config=\"http://scap.nist.gov/schema/configuration/0.1\" "
        "xmlns:meta=\"http://scap.nist.gov/schema/cpe-dictionary-metadata/"
        "0.2\" xmlns:cpe-23=\"http://scap.nist.gov/schema/cpe-extension/2.3\" "
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
        "xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.3\" "
        "xsi:schemaLocation=\"http://cpe.mitre.org/dictionary/2.0 "
        "https://scap.nist.gov/schema/cpe/2.2/cpe-dictionary_2.2.xsd "
        "http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 "
        "https://scap.nist.gov/schema/cpe/2.1/cpe-dictionary-metadata_0.2.xsd "
        "http://scap.nist.gov/schema/scap-core/0.3 "
        "https://scap.nist.gov/schema/nvd/scap-core_0.3.xsd "
        "http://scap.nist.gov/schema/configuration/0.1 "
        "https://scap.nist.gov/schema/nvd/configuration_0.1.xsd "
        "http://scap.nist.gov/schema/scap-core/0.1 "
        "https://scap.nist.gov/schema/nvd/scap-core_0.1.xsd\">"
        "  <cpe-item "
        "name=\"cpe:/"
        "a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~\">"
        "    <title xml:lang=\"en-US\">$0.99 Kindle Books project $0.99 Kindle "
        "Books (aka com.kindle.books.for99) for android 6.0</title>"
        "    <references>"
        "      <reference "
        "href=\"https://play.google.com/store/apps/"
        "details?id=com.kindle.books.for99\">Product information</reference>"
        "      <reference "
        "href=\"https://docs.google.com/spreadsheets/d/"
        "1t5GXwjw82SyunALVJb2w0zi3FoLRIkfGPc7AMjRF0r4/"
        "edit?pli=1#gid=1053404143\">Government Advisory</reference>"
        "    </references>"
        "    <meta:item-metadata nvd-id=\"289692\" status=\"FINAL\" "
        "modification-date=\"2014-11-10T17:01:25.103Z\"/>"
        "  </cpe-item>"
        "</cpe-list>";

  assert_that (parse_element (xml, &element), is_equal_to (0));

  assert_that (element_name (element), is_equal_to_string ("cpe-list"));
  item = element_child (element, "cpe-item");
  assert_that (item, is_not_null);
  meta = element_child (item, "item-metadata");
  assert_that (meta, is_not_null);
  // NB
  assert_that (element_name (meta), is_equal_to_string ("item-metadata"));
  // assert_that (element_name (meta), is_equal_to_string
  // ("meta:item-metadata"));
}

Ensure (xmlutils, parse_element_item_handles_cdata)
{
  element_t element;
  const gchar *xml;

  xml =
    "<description><![CDATA[Several vulnerabilities were discovered in the "
    "Chromium browser. The Common Vulnerabilities and Exposures project "
    "identifies the following problems: CVE-2011-1108 Google Chrome before "
    "9.0.597.107 does not properly implement JavaScript dialogs, which allows "
    "remote attackers to cause a denial of service or possibly have "
    "unspecified other impact via a crafted HTML document. CVE-2011-1109 "
    "Google Chrome before 9.0.597.107 does not properly process nodes in "
    "Cascading Style Sheets stylesheets, which allows remote attackers to "
    "cause a denial of service or possibly have unspecified other impact via "
    "unknown vectors that lead to a &quot;stale pointer.&quot; CVE-2011-1113 "
    "Google Chrome before 9.0.597.107 on 64-bit Linux platforms does not "
    "properly perform pickle deserialization, which allows remote attackers to "
    "cause a denial of service via unspecified vectors. CVE-2011-1114 Google "
    "Chrome before 9.0.597.107 does not properly handle tables, which allows "
    "remote attackers to cause a denial of service or possibly have "
    "unspecified other impact via unknown vectors that lead to a &quot;stale "
    "node.&quot; CVE-2011-1115 Google Chrome before 9.0.597.107 does not "
    "properly render tables, which allows remote attackers to cause a denial "
    "of service or possibly have unspecified other impact via unknown vectors "
    "that lead to a &quot;stale pointer.&quot; CVE-2011-1121 Integer overflow "
    "in Google Chrome before 9.0.597.107 allows remote attackers to cause a "
    "denial of service or possibly have unspecified other impact via vectors "
    "involving a TEXTAREA element. CVE-2011-1122 The WebGL implementation in "
    "Google Chrome before 9.0.597.107 allows remote attackers to cause a "
    "denial of service via unspecified vectors, aka Issue 71960. In addition, "
    "this upload fixes the following issues : Out-of-bounds read in text "
    "searching [69640] Memory corruption in SVG fonts. [72134] Memory "
    "corruption with counter nodes. [69628] Stale node in box layout. [70027] "
    "Cross-origin error message leak with workers. [70336] Stale pointer in "
    "table painting. [72028] Stale pointer with SVG cursors. "
    "[73746]]]></description>";

  assert_that (parse_element (xml, &element), is_equal_to (0));
  assert_that (element_name (element), is_equal_to_string ("description"));
  assert_that (
    element_text (element),
    is_equal_to_string (
      "Several vulnerabilities were discovered in the Chromium browser. The "
      "Common Vulnerabilities and Exposures project identifies the following "
      "problems: CVE-2011-1108 Google Chrome before 9.0.597.107 does not "
      "properly implement JavaScript dialogs, which allows remote attackers to "
      "cause a denial of service or possibly have unspecified other impact via "
      "a crafted HTML document. CVE-2011-1109 Google Chrome before 9.0.597.107 "
      "does not properly process nodes in Cascading Style Sheets stylesheets, "
      "which allows remote attackers to cause a denial of service or possibly "
      "have unspecified other impact via unknown vectors that lead to a "
      "&quot;stale pointer.&quot; CVE-2011-1113 Google Chrome before "
      "9.0.597.107 on 64-bit Linux platforms does not properly perform pickle "
      "deserialization, which allows remote attackers to cause a denial of "
      "service via unspecified vectors. CVE-2011-1114 Google Chrome before "
      "9.0.597.107 does not properly handle tables, which allows remote "
      "attackers to cause a denial of service or possibly have unspecified "
      "other impact via unknown vectors that lead to a &quot;stale node.&quot; "
      "CVE-2011-1115 Google Chrome before 9.0.597.107 does not properly render "
      "tables, which allows remote attackers to cause a denial of service or "
      "possibly have unspecified other impact via unknown vectors that lead to "
      "a &quot;stale pointer.&quot; CVE-2011-1121 Integer overflow in Google "
      "Chrome before 9.0.597.107 allows remote attackers to cause a denial of "
      "service or possibly have unspecified other impact via vectors involving "
      "a TEXTAREA element. CVE-2011-1122 The WebGL implementation in Google "
      "Chrome before 9.0.597.107 allows remote attackers to cause a denial of "
      "service via unspecified vectors, aka Issue 71960. In addition, this "
      "upload fixes the following issues : Out-of-bounds read in text "
      "searching [69640] Memory corruption in SVG fonts. [72134] Memory "
      "corruption with counter nodes. [69628] Stale node in box layout. "
      "[70027] Cross-origin error message leak with workers. [70336] Stale "
      "pointer in table painting. [72028] Stale pointer with SVG cursors. "
      "[73746]"));
}

/* element_next. */

Ensure (xmlutils, element_next_handles_multiple_children)
{
  element_t element, child;
  const gchar *xml;

  xml = "<top><a>1</a><b>2</b><c>3</c></top>";

  assert_that (parse_element (xml, &element), is_equal_to (0));

  assert_that (element_name (element), is_equal_to_string ("top"));

  child = element_first_child (element);
  assert_that (child, is_not_null);
  assert_that (element_name (child), is_equal_to_string ("a"));
  assert_that (element_text (child), is_equal_to_string ("1"));

  child = element_next (child);
  assert_that (child, is_not_null);
  assert_that (element_name (child), is_equal_to_string ("b"));
  assert_that (element_text (child), is_equal_to_string ("2"));

  child = element_next (child);
  assert_that (child, is_not_null);
  assert_that (element_name (child), is_equal_to_string ("c"));
  assert_that (element_text (child), is_equal_to_string ("3"));
}

Ensure (xmlutils, parse_element_free_using_child)
{
  element_t element;
  const gchar *xml;

  xml = "<a><b><c>1</c></b></a>";

  assert_that (parse_element (xml, &element), is_equal_to (0));
  assert_that (element_name (element), is_equal_to_string ("a"));
  element = element_child (element, "b");
  assert_that (element, is_not_null);
  element = element_child (element, "c");
  assert_that (element, is_not_null);
  element_free (element);
}

Ensure (xmlutils, print_element_to_string_prints)
{
  element_t element;
  const gchar *xml;
  GString *str;

  xml = "<a aa=\"1\">a text<b><c ca=\"x\" ca2=\"y\">1</c><d/><e></e></b> and "
        "more a text</a>";
  str = g_string_new ("");

  assert_that (parse_element (xml, &element), is_equal_to (0));
  print_element_to_string (element, str);
  assert_that (str->str, is_equal_to_string (
                           "<a aa=\"1\">a text and more a text<b><c ca=\"x\" "
                           "ca2=\"y\">1</c><d></d><e></e></b></a>"));
  g_string_free (str, TRUE);
  element_free (element);
}

Ensure (xmlutils, depth1_returns_top_level_children_in_order)
{
  const char *xml = "<root>"
                    "  <a x='1'>A</a>"
                    "  <b>B</b>"
                    "  <c><d>D</d></c>"
                    "</root>";

  gchar *path = write_temp_xml (xml);
  assert_that (path, is_not_null);

  xml_file_iterator_t it = xml_file_iterator_new ();
  assert_that (xml_file_iterator_init_from_file_path (it, path, 1),
               is_equal_to (0));

  gchar *err = NULL;
  element_t e;

  e = xml_file_iterator_next (it, &err);
  assert_that (err, is_null);
  assert_that (e, is_not_null);
  assert_that (element_name (e), is_equal_to_string ("a"));
  assert_that (element_text (e), is_equal_to_string ("A"));
  element_free (e);

  e = xml_file_iterator_next (it, &err);
  assert_that (err, is_null);
  assert_that (e, is_not_null);
  assert_that (element_name (e), is_equal_to_string ("b"));
  assert_that (element_text (e), is_equal_to_string ("B"));
  element_free (e);

  e = xml_file_iterator_next (it, &err);
  assert_that (err, is_null);
  assert_that (e, is_not_null);
  assert_that (element_name (e), is_equal_to_string ("c"));
  element_t d = element_child (e, "d");
  assert_that (d, is_not_null);
  assert_that (element_text (d), is_equal_to_string ("D"));
  element_free (e);

  e = xml_file_iterator_next (it, &err);
  assert_that (e, is_null);
  assert_that (err, is_null);

  xml_file_iterator_free (it);
  g_unlink (path);
  g_free (path);
}

Ensure (xmlutils, depth2_returns_grandchildren)
{
  const char *xml = "<root>"
                    "  <a>A</a>"
                    "  <c><d id='1'>D</d><d id='2'>E</d></c>"
                    "</root>";

  gchar *path = write_temp_xml (xml);
  assert_that (path, is_not_null);

  xml_file_iterator_t it = xml_file_iterator_new ();
  assert_that (xml_file_iterator_init_from_file_path (it, path, 2),
               is_equal_to (0));

  gchar *err = NULL;
  element_t e;

  // a has no grandchildren (depth2 under root), but iterator will yield
  // the d nodes when closing their parent <c>
  e = xml_file_iterator_next (it, &err);
  assert_that (err, is_null);
  assert_that (e, is_not_null);
  assert_that (element_name (e), is_equal_to_string ("d"));
  assert_that (element_attribute (e, "id"), is_equal_to_string ("1"));
  element_free (e);

  e = xml_file_iterator_next (it, &err);
  assert_that (err, is_null);
  assert_that (e, is_not_null);
  assert_that (element_name (e), is_equal_to_string ("d"));
  assert_that (element_attribute (e, "id"), is_equal_to_string ("2"));
  element_free (e);

  e = xml_file_iterator_next (it, &err);
  assert_that (e, is_null);
  assert_that (err, is_null);

  xml_file_iterator_free (it);
  g_unlink (path);
  g_free (path);
}

Ensure (xmlutils, rewind_resets_state)
{
  const char *xml = "<root><x>1</x><y>2</y></root>";
  gchar *path = write_temp_xml (xml);
  assert_that (path, is_not_null);

  xml_file_iterator_t it = xml_file_iterator_new ();
  assert_that (xml_file_iterator_init_from_file_path (it, path, 1),
               is_equal_to (0));

  gchar *err = NULL;
  element_t e;

  e = xml_file_iterator_next (it, &err);
  assert_that (element_name (e), is_equal_to_string ("x"));
  element_free (e);

  assert_that (xml_file_iterator_rewind (it), is_equal_to (0));

  e = xml_file_iterator_next (it, &err);
  assert_that (element_name (e), is_equal_to_string ("x"));
  element_free (e);

  e = xml_file_iterator_next (it, &err);
  assert_that (element_name (e), is_equal_to_string ("y"));
  element_free (e);

  xml_file_iterator_free (it);
  g_unlink (path);
  g_free (path);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, xmlutils, parse_entity_parses_simple_xml);
  add_test_with_context (suite, xmlutils,
                         parse_entity_parses_xml_with_attributes);
  add_test_with_context (suite, xmlutils, parse_entity_handles_declaration);
  add_test_with_context (suite, xmlutils, parse_entity_handles_namespace);
  add_test_with_context (suite, xmlutils, parse_entity_oval_timestamp);

  add_test_with_context (suite, xmlutils,
                         next_entities_handles_multiple_children);

  add_test_with_context (suite, xmlutils, parse_element_parses_simple_xml);
  add_test_with_context (suite, xmlutils,
                         parse_element_parses_xml_with_attributes);
  add_test_with_context (suite, xmlutils, parse_element_handles_declaration);
  add_test_with_context (suite, xmlutils, parse_element_handles_namespace);
  add_test_with_context (suite, xmlutils, parse_element_oval_timestamp);
  add_test_with_context (suite, xmlutils, parse_element_item_metadata);
  add_test_with_context (suite, xmlutils,
                         parse_element_item_metadata_with_namespace);
  add_test_with_context (suite, xmlutils, parse_element_item_handles_cdata);
  add_test_with_context (suite, xmlutils, parse_element_free_using_child);

  add_test_with_context (suite, xmlutils, print_element_to_string_prints);

  add_test_with_context (suite, xmlutils,
                         element_next_handles_multiple_children);

  add_test_with_context (suite, xmlutils,
                         depth1_returns_top_level_children_in_order);

  add_test_with_context (suite, xmlutils, depth2_returns_grandchildren);

  add_test_with_context (suite, xmlutils, rewind_resets_state);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}

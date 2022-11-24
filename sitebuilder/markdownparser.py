import markdown, os, random
import sitebuilder.fileparser as fileparser
from bs4 import BeautifulSoup

SECTION_STYLES = [
    "style1",
    "style2",
    "style3",
    "style4",
    "style5",
    "style6"
]

BASE_HTML_LOC = os.path.join('.', 'templates', 'base.html')

def _wrap_body(html_processed):
    return '<section id="wrapper">\r\n' + html_processed + '</section>\r\n'

def _create_sections(soup, prop_dict):
    section_list = soup.prettify().split("<hr/>")
    section_styles = SECTION_STYLES.copy()

    for i, section in enumerate(section_list):
        alt_str = "alt" if i % 2 == 1 else ""

        if len(section_styles) == 0:
            section_styles = SECTION_STYLES.copy()

        s_style = random.choice(section_styles)
        section_styles.remove(s_style)

        if i == 0 and prop_dict.get("show_header_section", True):
            new_section = '<section class="wrapper spotlight {style} {alt_str}">\r\n'.format(style=s_style, alt_str=alt_str)
        else:
            new_section = '<section class="wrapper {style} {alt_str}">\r\n'.format(style=s_style, alt_str=alt_str)

        new_section = new_section + '<div class="inner">\r\n'
        if i == 0 and prop_dict.get("show_header_section", True):
            new_section = new_section + '<div class="main_image"><img src={} alt="" /></div>\r\n'.format(prop_dict.get("main_image"))
        new_section = new_section + '<div class="content">\r\n'
        new_section = new_section + section
        new_section = new_section + "</div>\r\n"
        new_section = new_section + "</div>\r\n"
        new_section = new_section + "</section>\r\n"

        section_list[i] = new_section

    return _wrap_body(''.join(section_list))

def _modify_attrs(tag_name, attrs, soup):
    for tag in soup.find_all(tag_name):
      for attr_name, attr_value in attrs.items():
          tag[attr_name] = attr_value

def _change_img_srcs(name, group_name, soup):
    new_img_folder = "/images/{group_name}/{name}/".format(group_name=group_name,
                                                            name=name)
    for img_tag in soup.find_all("img"):
        if img_tag.get("src", False):
            img_tag["src"] = new_img_folder + img_tag["src"].split("/")[-1]
            img_tag["class"] = "center"


def compile_markdown(name, path, group_name, compiled_folder):
    md_file = os.path.join(path, "content.md")
    with open(md_file, 'r') as f:
        md_raw = f.read()
    soup = BeautifulSoup(markdown.markdown(md_raw, extensions=["fenced_code", "codehilite", "markdown.extensions.tables", "nl2br", "toc"]), "html.parser")

    _modify_attrs("h1", {"class":"major"}, soup)
    _modify_attrs("h2", {"class":"major"}, soup)
    _modify_attrs("h3", {"class":"major"}, soup)

    _change_img_srcs(name, group_name, soup)

    prop_dict = fileparser.load_page_config(name, path, group_name)

    prop_dict["html"] = _create_sections(soup, prop_dict)

    return prop_dict

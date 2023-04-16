from sitebuilder.fileparser import parse_pages
import datetime, os, random, shutil
from jinja2 import Environment, FileSystemLoader, select_autoescape

class PageControl:
    DEFAULT_PASS_MSG = "Submit the password for this page to gain access!"
    IMG_FOLDER = "/images/{page_group_name}/{img_path}"
    SECTION_STYLES = [
        "style1",
        "style2",
        "style3",
        "style4",
        "style5",
        "style6"
    ]

    def __init__(self, page_group_name, markdown_folder, section_name, section_desc):
        self.page_group_name = page_group_name
        self.section_name = section_name
        self.section_desc = section_desc
        self.categories = {}
        self.page_configs = parse_pages(page_group_name, markdown_folder)
        self.add_page_configs(self.page_configs)

    def render_pages(self, jinja_env: Environment, html_folder):
        for path in self.published_pages:
            page_config = self.page_configs[path]
            release_date = page_config.get("release_date").strftime("%Y-%m-%d") if page_config.get("release_date", False) else ""
            html_page_folder = os.path.join(html_folder, path)
            os.makedirs(html_page_folder, exist_ok=True)
            html_path = os.path.join(html_page_folder, "index.html")
            template = jinja_env.get_template("article.html")
            template_str = template.render(
                name = page_config["page_name"],
                description = page_config["desc"],
                date = release_date,
                body = page_config["html"],
                image = page_config["main_image"] if "main_image" in page_config else None
            )
            with open(html_path, "w") as f:
                f.write(template_str)

    def _sort_pages(self, pages):
        return sorted(pages,
                        key=lambda path : self.page_configs[path]["release_date"],
                        reverse=True)

    def _update_recent_categories(self):
        self.recent_categories = sorted(list(self.categories.keys()),
            key=lambda category: self._sort_pages(self.categories[category])[0],
            reverse=True)
        self.update_page_lists()

    def _sort_categories(self):
        for category in self.categories:
            self.categories[category] = self._sort_pages(self.categories[category])
        self._update_recent_categories()

    def _update_categories(self, path):
        category = self.page_configs[path].get("category", "None")
        self.categories[category] = self._sort_pages(self.categories.get(category, []) + [path])
        self._update_recent_categories()
        self.update_page_lists()

    def add_page_configs(self, page_configs):
        self.published_pages = {}

        for name in page_configs:
            page_config = page_configs[name]

            if page_config.get("publish", False):
                self.published_pages[name] = page_config.get("template_loc")
                self.categories[page_config.get("category", "General")] = self.categories.get(page_config.get("category", "None"), []) + [name]

        self._sort_categories()

    def update_page_lists(self):
        category_page_lists = []
        most_recent_article = None
        for category in self.recent_categories:
            page_list = []
            for path in self.categories[category]:
                page_config = self.page_configs[path]
                page_details = {
                    "page_name" : page_config["page_name"],
                    "desc" : page_config["desc"],
                    "release_date" : page_config["release_date"],
                    "url_loc" : "/" + self.page_group_name + "/" + page_config["name"] + "/"
                }
                if page_config.get("main_image", False):
                    page_details["main_image"] = page_config["main_image"]
                page_list.append(page_details)

                if most_recent_article == None:
                    most_recent_article = page_details
                elif page_details["release_date"] > most_recent_article["release_date"]:
                    most_recent_article = page_details
            category_page_lists.append({category:page_list})
        self.page_lists = category_page_lists
        self.most_recent_article = most_recent_article

    def render_pages_list(self, jinja_env: Environment, html_folder):
        alt_list = ["alt" if i % 2 == 0 else "" for i in range(len(self.recent_categories))]
        style_list = [random.choice(PageControl.SECTION_STYLES) for _i in range(len(self.recent_categories))]
        template = jinja_env.get_template("article_overview.html")
        template_str = template.render(
            section_name=self.section_name,
            section_desc=self.section_desc,
            page_lists = self.page_lists,
            most_recent_article = self.most_recent_article,
            alt_list=alt_list,
            style_list=style_list
        )
        output_path = os.path.join(html_folder, "index.html")
        with open(output_path, "w") as f:
            f.write(template_str)

class TemplateRenderer:

    def __init__(self, writeup_controller: PageControl, blog_controller: PageControl):
        self.jinja_env = Environment(
            loader=FileSystemLoader(os.path.join(".", "templates")),
            autoescape=select_autoescape()
        )
        self.writeup_c = writeup_controller
        self.blog_c = blog_controller
        
    def render_pages_from_controller(self, pc: PageControl):
        html_folder = os.path.join("html", pc.page_group_name)
        os.makedirs(html_folder, exist_ok=True)
        cat_index_html = pc.render_pages_list(self.jinja_env, html_folder)
        cat_pages = pc.render_pages(self.jinja_env, html_folder)

    def render_all(self):
        os.makedirs("html", exist_ok=True)
        index_template = self.jinja_env.get_template("index.html")
        index_html = index_template.render(
            latest_writeup=self.writeup_c.most_recent_article,
            latest_blog=self.blog_c.most_recent_article
        )
        with open(os.path.join("html", "index.html"), "w") as f:
            f.write(index_html)
        self.render_pages_from_controller(self.writeup_c)
        self.render_pages_from_controller(self.blog_c)

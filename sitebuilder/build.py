from sitebuilder.pagecontrol import PageControl, TemplateRenderer
import os

WRITEUPS_FOLDER = os.path.join(".", "markdown_entries", "writeups")
BLOG_FOLDER = os.path.join(".", "markdown_entries", "blog")

def build():
    writeups_controller = PageControl("writeups", WRITEUPS_FOLDER, "CTF Writeups", "Where I Document My Misfortunes Completing CTF Challenges and HackTheBox Machines")
    blog_controller = PageControl("blog", BLOG_FOLDER, "Blog Articles", "Blog articles about my shenanigans in Cyber Security and Computer Science")
    template_renderer = TemplateRenderer(writeups_controller, blog_controller)
    template_renderer.render_all()

if __name__ == "__main__":
    build()

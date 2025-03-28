from docxtpl import RichText
import markdown
from html.parser import HTMLParser
from html import escape, unescape

# report generator parser class
class MyHTMLParser(HTMLParser):
    current_tag = ""
    current_attrs = []
    images = {}
    is_ordered_list = False
    list_id = 1
    rt = RichText()

    def clearRichText(self):
        empty_rt = RichText()
        self.rt = empty_rt

    def getRichText(self):
        return self.rt
    
    def getImages(self):
        return self.images

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        self.current_attrs = attrs

        # handle images here to fix broken image generation when no text after image
        if tag == "img":
            img_path = self.current_attrs[1][1]

            # replace `/` and `-` characters due to jinja errors
            img_id = f"image{(img_path.split("/")[-1]).replace("-", "")}"
                
            img_src = "." + img_path + ".png"
            img_desc = self.current_attrs[0][1]

            self.images[img_id] = img_src
            img_placeholder = "{{ " + img_id + " }}"
                
            self.rt.add(img_placeholder)
            self.rt.add("\n")
            self.rt.add(f"Image {len(self.images)} {img_desc}", style="descriptionunderimage")
            self.rt.add("\n")

    def handle_endtag(self, tag):
        match tag:
            case "ol":
                self.is_ordered_list = False
                self.list_id = 1
            case "ul":
                self.list_id = 1
            case _:
                return
    
    def handle_data(self, data):
        data = unescape(data)

        match self.current_tag:
            case "h1":
                self.rt.add(data, style="heading1")
        
            case "h2":
                self.rt.add(data, style="heading2")
        
            case "h3":
                self.rt.add(data, style="heading3")
        
            case "h4":
                self.rt.add(data)
        
            case "h5":
                self.rt.add(data)
        
            case "h6":
                self.rt.add(data)
        
            case "p":
                self.rt.add(data)
        
            case "strong":
                self.rt.add(data, bold=True)
                # fallback to paragraph due to parsing errors
                self.current_tag = "p"
        
            case "em":
                self.rt.add(data, italic=True)
                # fallback to paragraph due to parsing errors
                self.current_tag = "p"
        
            case "blockquote":
                self.rt.add(data)
                # fallback to paragraph due to parsing errors
                self.current_tag = "p"
        
            case "code":
                if "\n" in data:
                    self.rt.add(data,style="codeblock")
                    # fallback to paragraph due to parsing errors
                    self.current_tag = "p"
                else:
                    self.rt.add(data,style="codesnippet")
                    # fallback to paragraph due to parsing errors                    
                    self.current_tag = "p"

            case "ol":
                self.is_ordered_list = True
        
            case "li":
                if data != "\n" and not self.is_ordered_list:
                    self.rt.add("    • " + data)
                elif data != "\n" and self.is_ordered_list:
                    self.rt.add(f"   {self.list_id}. " + data)
                    self.list_id += 1
                else:
                    self.rt.add(data)

            case "a":
                self.rt.add(data)
        
            case _:
                self.rt.add(data)

# report context parser function
def parseContext(context, images):

    # ssti fix
    content = escape(context).replace('{{'.format(), '{/')
    # fenced_code extension to add support for multiline code fragments styling
    content_html = markdown.markdown(content, extensions=['fenced_code'])
    
    parser = MyHTMLParser()
    parser.clearRichText()

    parser.feed(content_html)

    images.update(parser.getImages())

    return parser.getRichText()
"""Helper module of the EZLARP Python sample."""


class Banner:
    def __init__(self, text):
        self.text = text

    def render(self, width=40):
        return self.text.center(width, "=")


def banner(text):
    return Banner(text).render()

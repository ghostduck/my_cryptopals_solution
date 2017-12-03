def print_bytes_with_description(b_s, description="", *args):
    # print "1100ff..." from byte array(b_s)
    show_byte_message = "".join("{0:02x}".format(k) for k in b_s)
    print(description, show_byte_message, *args)

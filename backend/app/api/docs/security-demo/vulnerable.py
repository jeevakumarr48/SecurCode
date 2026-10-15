def unsafe_expression(user_input):
    return eval(user_input)


def unsafe_command(user_input):
    import subprocess
    return subprocess.call(user_input, shell=True)
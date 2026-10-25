"""Compatibility stub: this deployment is strictly offline."""


def available():
    return False


async def call_llm_json(*_args, **_kwargs):
    raise RuntimeError("Model providers are disabled in the offline solver")

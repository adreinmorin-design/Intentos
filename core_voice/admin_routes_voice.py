from fastapi import APIRouter, UploadFile, File
from pathlib import Path
from voice_manager import VoiceManager

router = APIRouter(prefix="/admin/voice", tags=["admin-voice"])
voice_manager = VoiceManager(base_dir=Path("./voice_profiles"))

@router.post("/upload")
async def upload_voice(user_id: str, file: UploadFile = File(...)):
    audio_path = Path(f"./temp/{file.filename}")
    with audio_path.open("wb") as f:
        f.write(await file.read())
    return {"message": voice_manager.upload_voice(user_id, audio_path)}

@router.post("/switch")
def switch_voice(user_id: str):
    return {"message": voice_manager.switch_voice(user_id)}
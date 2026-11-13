"""Start AccessFlow V2 in local-lab mode (single command)."""
import argparse
import uvicorn

if __name__=='__main__':
    p=argparse.ArgumentParser(description='Run AccessFlow V2 on localhost')
    p.add_argument('--port',type=int,default=8000)
    args=p.parse_args()
    print('\n  AccessFlow V2 — Local Security Workflow Lab')
    print(f'  URL: http://127.0.0.1:{args.port}')
    print('  Ctrl+C de dung ung dung\n')
    uvicorn.run('backend.app:app',host='127.0.0.1',port=args.port,reload=False,log_level='warning')
